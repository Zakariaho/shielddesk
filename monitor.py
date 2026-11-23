"""monitor.py - ShieldDesk security-event monitor (CYS 401 project, Task 5).

Reads the authentication log written by the app:
    2026-11-16 10:42:07 | LOGIN_FAILED | user=student01 | ip=127.0.0.1

Detection rules
  R1 BRUTE_FORCE         (HIGH)     >= 5 LOGIN_FAILED from one IP within 60 seconds
  R2 POSSIBLE_COMPROMISE (CRITICAL) LOGIN_SUCCESS for a user who had >= 5 failures
                                    in the previous 5 minutes

Alerts are printed and appended to logs/alerts.log.

Usage
  python3 monitor.py logs/auth.log              scan a whole log file
  python3 monitor.py logs/auth.log --follow     keep watching for new lines (live)
"""
import argparse
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<event>[A-Z_]+) "
    r"\| user=(?P<user>\S*) \| ip=(?P<ip>\S*)")

FAIL_THRESHOLD = 5
BRUTE_WINDOW = timedelta(seconds=60)
COMPROMISE_WINDOW = timedelta(minutes=5)
ALERT_LOG = "logs/alerts.log"


class Monitor:
    def __init__(self):
        self.fails_by_ip = defaultdict(deque)    # ip -> timestamps of recent failures
        self.fails_by_user = defaultdict(deque)  # user -> timestamps of recent failures
        self.alerted_until = {}                  # ip -> end of the burst already alerted
        self.alerts = 0

    def alert(self, ts, severity, rule, detail):
        self.alerts += 1
        line = f"{ts:%Y-%m-%d %H:%M:%S} | ALERT | {severity} | {rule} | {detail}"
        print(line)
        with open(ALERT_LOG, "a") as f:
            f.write(line + "\n")

    def process(self, raw):
        m = LINE_RE.match(raw.strip())
        if not m:
            return
        ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S")
        event, user, ip = m["event"], m["user"], m["ip"]

        if event == "LOGIN_FAILED":
            ip_q, user_q = self.fails_by_ip[ip], self.fails_by_user[user]
            ip_q.append(ts)
            user_q.append(ts)
            while ip_q and ts - ip_q[0] > BRUTE_WINDOW:
                ip_q.popleft()
            while user_q and ts - user_q[0] > COMPROMISE_WINDOW:
                user_q.popleft()
            # R1: one alert per burst, not one per extra failure
            if len(ip_q) >= FAIL_THRESHOLD and ts > self.alerted_until.get(ip, datetime.min):
                self.alert(ts, "HIGH", "BRUTE_FORCE",
                           f"{len(ip_q)} failed logins from ip={ip} in "
                           f"{int((ts - ip_q[0]).total_seconds())}s (last user={user})")
                self.alerted_until[ip] = ts + BRUTE_WINDOW

        elif event == "LOGIN_SUCCESS":
            user_q = self.fails_by_user[user]
            while user_q and ts - user_q[0] > COMPROMISE_WINDOW:
                user_q.popleft()
            if len(user_q) >= FAIL_THRESHOLD:
                self.alert(ts, "CRITICAL", "POSSIBLE_COMPROMISE",
                           f"user={user} logged in from ip={ip} after "
                           f"{len(user_q)} failed attempts in the last 5 min")
            user_q.clear()


def main():
    ap = argparse.ArgumentParser(description="ShieldDesk auth-log monitor")
    ap.add_argument("logfile", nargs="?", default="logs/auth.log")
    ap.add_argument("--follow", action="store_true", help="keep watching for new lines")
    args = ap.parse_args()

    mon = Monitor()
    with open(args.logfile) as f:
        for raw in f:
            mon.process(raw)
        print(f"[monitor] scanned {args.logfile}: {mon.alerts} alert(s)")
        if args.follow:
            print("[monitor] watching for new events (Ctrl+C to stop)...")
            try:
                while True:
                    raw = f.readline()
                    if raw:
                        mon.process(raw)
                    else:
                        time.sleep(0.5)
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
