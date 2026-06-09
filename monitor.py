#!/usr/bin/env python3
"""
monitor.py — Suricata EVE JSON real-time alert monitor
Tails eve.json, parses alerts, sends notifications, and exports stats.
"""

import json
import time
import os
import sys
import signal
import argparse
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ids-monitor")

# ── ANSI colors ────────────────────────────────────────────────
C = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[0;31m",
    "MEDIUM":   "\033[0;33m",
    "LOW":      "\033[0;32m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "CYAN":     "\033[0;36m",
}

SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

# ── Notifier stubs ─────────────────────────────────────────────
def send_telegram(token: str, chat_id: str, message: str):
    try:
        import requests
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"}, timeout=5)
    except Exception as e:
        log.warning(f"Telegram notification failed: {e}")


def send_slack(webhook_url: str, message: str):
    try:
        import requests
        requests.post(webhook_url, json={"text": message}, timeout=5)
    except Exception as e:
        log.warning(f"Slack notification failed: {e}")


def send_email(smtp_config: dict, subject: str, body: str):
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_config["from"]
        msg["To"] = smtp_config["to"]
        with smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587)) as s:
            s.starttls()
            s.login(smtp_config["user"], smtp_config["password"])
            s.sendmail(smtp_config["from"], smtp_config["to"], msg.as_string())
    except Exception as e:
        log.warning(f"Email notification failed: {e}")


# ── Alert class ────────────────────────────────────────────────
class Alert:
    def __init__(self, raw: dict):
        self.raw = raw
        self.timestamp = raw.get("timestamp", datetime.utcnow().isoformat())
        self.src_ip = raw.get("src_ip", "?")
        self.src_port = raw.get("src_port", 0)
        self.dest_ip = raw.get("dest_ip", "?")
        self.dest_port = raw.get("dest_port", 0)
        self.proto = raw.get("proto", "?")
        alert_data = raw.get("alert", {})
        self.signature = alert_data.get("signature", "Unknown")
        self.category = alert_data.get("category", "Unknown")
        self.severity_num = alert_data.get("severity", 3)
        self.severity = SEVERITY_MAP.get(self.severity_num, "LOW")
        self.sid = alert_data.get("signature_id", 0)

    def to_line(self) -> str:
        color = C.get(self.severity, "")
        reset = C["RESET"]
        return (
            f"{color}[{self.severity:8s}]{reset} "
            f"{C['CYAN']}{self.timestamp[11:19]}{reset} "
            f"{self.src_ip}:{self.src_port} → {self.dest_ip}:{self.dest_port} "
            f"({self.proto}) │ {self.signature}"
        )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "signature": self.signature,
            "category": self.category,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "proto": self.proto,
            "sid": self.sid,
        }

    def to_notification(self) -> str:
        return (
            f"🚨 <b>IDS Alert [{self.severity}]</b>\n"
            f"📋 {self.signature}\n"
            f"🌐 {self.src_ip} → {self.dest_ip}:{self.dest_port}\n"
            f"🕐 {self.timestamp[:19].replace('T', ' ')}"
        )


# ── Stats tracker ──────────────────────────────────────────────
class StatsTracker:
    def __init__(self, window_minutes: int = 5):
        self.window = timedelta(minutes=window_minutes)
        self.recent: deque = deque()
        self.total = defaultdict(int)
        self.by_src = defaultdict(int)
        self.by_severity = defaultdict(int)
        self.by_sig = defaultdict(int)

    def add(self, alert: Alert):
        now = datetime.utcnow()
        self.recent.append((now, alert))
        while self.recent and (now - self.recent[0][0]) > self.window:
            self.recent.popleft()
        self.total["count"] += 1
        self.by_src[alert.src_ip] += 1
        self.by_severity[alert.severity] += 1
        self.by_sig[alert.signature] += 1

    def print_summary(self):
        now = datetime.utcnow()
        recent_count = len(self.recent)
        print(f"\n{C['BOLD']}── Stats ({now.strftime('%H:%M:%S')}) ─────────────────────────────{C['RESET']}")
        print(f"  Total alerts:      {self.total['count']}")
        print(f"  Last 5 min:        {recent_count}")
        for sev, cnt in sorted(self.by_severity.items()):
            color = C.get(sev, "")
            print(f"  {color}{sev:10s}{C['RESET']}     {cnt}")
        if self.by_src:
            top_src = sorted(self.by_src.items(), key=lambda x: -x[1])[:5]
            print(f"  Top sources:")
            for ip, cnt in top_src:
                print(f"    {ip:<20} {cnt} alerts")
        print()


# ── File tailer ────────────────────────────────────────────────
class LogTailer:
    def __init__(self, path: str):
        self.path = path
        self._fh = None
        self._inode = None
        self._open()

    def _open(self):
        try:
            self._fh = open(self.path, "r")
            self._fh.seek(0, 2)  # Seek to end
            self._inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            self._fh = None
            self._inode = None

    def readlines(self):
        if not self._fh:
            self._open()
            if not self._fh:
                return

        # Detect rotation
        try:
            cur_inode = os.stat(self.path).st_ino
            if cur_inode != self._inode:
                log.info("Log file rotated, reopening...")
                self._fh.close()
                self._open()
        except FileNotFoundError:
            return

        while True:
            line = self._fh.readline()
            if not line:
                break
            yield line.strip()


# ── Main monitor ───────────────────────────────────────────────
class IDSMonitor:
    def __init__(self, config: dict):
        self.config = config
        self.eve_path = config.get("eve_json", "/var/log/suricata/eve.json")
        self.export_path = config.get("export_json", "/tmp/ids_alerts.jsonl")
        self.tailer = LogTailer(self.eve_path)
        self.stats = StatsTracker()
        self.alert_count = 0
        self.last_stats_print = time.time()
        self._running = True
        signal.signal(signal.SIGINT, self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

    def _handle_stop(self, signum, frame):
        log.info("Shutting down monitor...")
        self._running = False

    def should_notify(self, alert: Alert) -> bool:
        min_sev = self.config.get("notify_min_severity", "HIGH")
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(alert.severity) >= order.index(min_sev)

    def notify(self, alert: Alert):
        msg = alert.to_notification()
        tg = self.config.get("telegram", {})
        if tg.get("token") and tg.get("chat_id"):
            send_telegram(tg["token"], tg["chat_id"], msg)
        slack = self.config.get("slack_webhook")
        if slack:
            send_slack(slack, msg.replace("<b>", "*").replace("</b>", "*"))
        if alert.severity == "CRITICAL":
            smtp = self.config.get("smtp", {})
            if smtp.get("host"):
                send_email(smtp, f"IDS CRITICAL: {alert.signature}", msg)

    def export(self, alert: Alert):
        try:
            with open(self.export_path, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as e:
            log.warning(f"Export failed: {e}")

    def run(self):
        log.info(f"Monitoring: {self.eve_path}")
        log.info(f"Export:     {self.export_path}")
        print(f"\n{C['BOLD']}🛡️  IDS Traffic Monitor — Started{C['RESET']}")
        print(f"   {'Severity':<10} {'Time':<10} {'Source → Dest':<40} Signature")
        print("─" * 100)

        while self._running:
            for line in self.tailer.readlines():
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert = Alert(event)
                self.alert_count += 1
                self.stats.add(alert)
                self.export(alert)
                print(alert.to_line())

                if self.should_notify(alert):
                    self.notify(alert)

            # Print stats every 60s
            if time.time() - self.last_stats_print > 60:
                self.stats.print_summary()
                self.last_stats_print = time.time()

            time.sleep(0.5)

        self.stats.print_summary()
        log.info(f"Monitor stopped. Total alerts processed: {self.alert_count}")


# ── Entry point ────────────────────────────────────────────────
def load_config(path: str) -> dict:
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        log.warning("PyYAML not installed, using defaults")
        return {}
    except FileNotFoundError:
        return {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Traffic Monitor")
    parser.add_argument("--config", "-c", default="config.yaml", help="Config file path")
    parser.add_argument("--eve", "-e", help="Override eve.json path")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.eve:
        config["eve_json"] = args.eve

    monitor = IDSMonitor(config)
    monitor.run()
