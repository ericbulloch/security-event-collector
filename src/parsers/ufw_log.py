import re
from datetime import datetime
from typing import Optional

from src.parsers.base import BaseParser

_UFW_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+kernel:.*"
    r"\[UFW (?P<action>BLOCK|ALLOW)\].*"
    r"SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*"
    r"PROTO=(?P<proto>\S+)"
    r"(?:.*SPT=(?P<src_port>\d+))?(?:.*DPT=(?P<dst_port>\d+))?"
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


class UfwLogParser(BaseParser):
    def parse(self, line: str) -> Optional[dict]:
        if "[UFW" not in line:
            return None

        m = _UFW_RE.search(line)
        if not m:
            return None

        action = "blocked" if m["action"] == "BLOCK" else "allowed"
        severity = "medium" if action == "blocked" else "low"
        dst_port = m.group("dst_port")
        src_port = m.group("src_port")

        return {
            "timestamp": _syslog_ts(m["month"], m["day"], m["time"]),
            "source": self.source,
            "event_type": "network_connection",
            "severity": severity,
            "user": None,
            "action": action,
            "resource": f"{m['dst_ip']}:{dst_port}" if dst_port else m["dst_ip"],
            "details": {
                "ip": m["src_ip"],
                "dst_ip": m["dst_ip"],
                "dst_port": int(dst_port) if dst_port else None,
                "src_port": int(src_port) if src_port else None,
                "protocol": m["proto"],
            },
            "raw_log": line,
        }
