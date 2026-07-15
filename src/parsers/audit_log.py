import re
from datetime import datetime
from typing import Dict, Optional

from src.parsers.base import BaseParser

_SYSCALL_RE = re.compile(
    r"type=SYSCALL msg=audit\(\d+\.\d+:(?P<seq>\d+)\):.*"
    r"syscall=(?P<syscall>\d+)"
    r"(?:.*uid=(?P<uid>\d+))?"
    r"(?:.*exe=\"(?P<exe>[^\"]+)\")?"
)

_PATH_RE = re.compile(
    r"type=PATH msg=audit\(\d+\.\d+:(?P<seq>\d+)\):.*"
    r"name=\"(?P<name>[^\"]+)\""
)

# x86_64 open / openat syscall numbers
_OPEN_SYSCALLS = {2, 257}

_SENSITIVE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/.ssh/",
    "/root/", "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa",
    ".bash_history", "/proc/", "/var/log/auth", "/var/log/secure",
)


def _is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(s in low for s in _SENSITIVE_PATHS)


class AuditLogParser(BaseParser):
    def __init__(self) -> None:
        # seq -> {exe, uid, raw_log} for unmatched SYSCALL records
        self._pending: Dict[str, dict] = {}
        self._line_count = 0

    def parse(self, line: str) -> Optional[dict]:
        self._line_count += 1

        # Prune buffer every 1,000 lines to prevent unbounded growth.
        if self._line_count % 1000 == 0 and len(self._pending) > 100:
            keys = list(self._pending.keys())
            for k in keys[:-50]:
                del self._pending[k]

        if line.startswith("type=SYSCALL"):
            m = _SYSCALL_RE.search(line)
            if m:
                try:
                    sc = int(m.group("syscall"))
                except (TypeError, ValueError):
                    sc = -1
                if sc in _OPEN_SYSCALLS:
                    self._pending[m.group("seq")] = {
                        "exe": m.group("exe"),
                        "uid": m.group("uid"),
                        "raw_log": line,
                    }
            return None

        if line.startswith("type=PATH"):
            m = _PATH_RE.search(line)
            if m:
                seq = m.group("seq")
                path = m.group("name")
                info = self._pending.pop(seq, None)
                if info and _is_sensitive(path):
                    uid = info.get("uid") or "unknown"
                    return {
                        "timestamp": datetime.utcnow().isoformat(),
                        "source": self.source,
                        "event_type": "file_access",
                        "severity": "high",
                        "user": uid,
                        "action": "accessed",
                        "resource": path,
                        "details": {
                            "exe": info.get("exe"),
                            "uid": uid,
                        },
                        "raw_log": info["raw_log"] + " | " + line,
                    }

        return None
