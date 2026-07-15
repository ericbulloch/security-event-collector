from datetime import datetime
from typing import Optional

from src.parsers.base import BaseParser


class WindowsFirewallLogParser(BaseParser):
    def parse(self, line: str) -> Optional[dict]:
        # Skip header comment lines and blank lines
        if not line.strip() or line.startswith("#"):
            return None

        parts = line.split()
        if len(parts) < 8:
            return None

        try:
            date_str, time_str, action, proto, src_ip, dst_ip, src_port, dst_port = (
                parts[0], parts[1], parts[2], parts[3],
                parts[4], parts[5], parts[6], parts[7],
            )
        except IndexError:
            return None

        action_upper = action.upper()
        if action_upper not in ("DROP", "ALLOW"):
            return None

        event_action = "blocked" if action_upper == "DROP" else "allowed"
        severity = "medium" if event_action == "blocked" else "low"

        try:
            ts = f"{date_str}T{time_str}"
            # Validate the timestamp is parseable
            datetime.fromisoformat(ts)
        except ValueError:
            ts = datetime.utcnow().isoformat()

        dst_port_int = int(dst_port) if dst_port.isdigit() else None
        src_port_int = int(src_port) if src_port.isdigit() else None

        return {
            "timestamp": ts,
            "source": self.source,
            "event_type": "network_connection",
            "severity": severity,
            "user": None,
            "action": event_action,
            "resource": f"{dst_ip}:{dst_port}" if dst_port_int else dst_ip,
            "details": {
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port_int,
                "src_port": src_port_int,
                "protocol": proto,
            },
            "raw_log": line,
        }
