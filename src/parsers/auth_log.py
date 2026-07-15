import re
from datetime import datetime
from typing import Optional

from src.parsers.base import BaseParser

# Jan 15 10:30:45 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
# Jan 15 10:30:45 hostname sshd[1234]: Failed password for invalid user admin from 1.2.3.4 ...
_FAILED_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port \d+"
)

# Jan 15 10:30:45 hostname sshd[1234]: Accepted password for alice from 1.2.3.4 port 54321 ssh2
_ACCEPTED_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port \d+"
)

# Jan 15 10:30:45 hostname sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
_SUDO_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sudo\s*:\s+"
    r"(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)"
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _syslog_ts(month: str, day: str, time_str: str) -> str:
    now = datetime.now()
    m = _MONTH_MAP.get(month, now.month)
    try:
        h, mn, s = time_str.split(":")
        return datetime(now.year, m, int(day), int(h), int(mn), int(s)).isoformat()
    except (ValueError, KeyError):
        return datetime.utcnow().isoformat()


class AuthLogParser(BaseParser):
    def parse(self, line: str) -> Optional[dict]:
        m = _FAILED_RE.search(line)
        if m:
            return {
                "timestamp": _syslog_ts(m["month"], m["day"], m["time"]),
                "source": self.source,
                "event_type": "login_attempt",
                "severity": "medium",
                "user": m["user"],
                "action": "failed",
                "resource": None,
                "details": {"ip": m["ip"], "method": "ssh"},
                "raw_log": line,
            }

        m = _ACCEPTED_RE.search(line)
        if m:
            return {
                "timestamp": _syslog_ts(m["month"], m["day"], m["time"]),
                "source": self.source,
                "event_type": "login_attempt",
                "severity": "low",
                "user": m["user"],
                "action": "success",
                "resource": None,
                "details": {"ip": m["ip"], "method": "ssh"},
                "raw_log": line,
            }

        m = _SUDO_RE.search(line)
        if m:
            return {
                "timestamp": _syslog_ts(m["month"], m["day"], m["time"]),
                "source": self.source,
                "event_type": "privilege_change",
                "severity": "medium",
                "user": m["user"],
                "action": "executed",
                "resource": m["cmd"].strip(),
                "details": {"type": "sudo"},
                "raw_log": line,
            }

        return None
