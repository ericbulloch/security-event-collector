import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Optional

import src.config as config
from src.local_queue import LocalQueue

logger = logging.getLogger(__name__)

_LOG_NAME = "Security"
_EVENT_IDS = [4625, 4624, 4672, 4663, 5156]

# XML namespace used by Windows event log XML
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Logon types that represent interactive or remote network sessions.
# Type 2=Interactive, 3=Network, 10=RemoteInteractive.
# Types 4 (Batch), 5 (Service), 7 (Unlock) generate high-frequency noise.
_REMOTE_LOGON_TYPES = {2, 3, 10}


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


def _data(event_data: ET.Element, name: str) -> str:
    el = event_data.find(f"e:Data[@Name='{name}']", _NS)
    return _text(el)


class WindowsEventLogPoller:

    def __init__(self, queue: LocalQueue) -> None:
        self.queue = queue

    def poll(self) -> int:
        last_record = self.queue.get_evtlog_record(_LOG_NAME)
        ids_filter = " or ".join(f"EventID={eid}" for eid in _EVENT_IDS)
        xpath = f"*[System[({ids_filter}) and (EventRecordID > {last_record})]]"

        xml_text = self._run_wevtutil(xpath)
        if not xml_text:
            return 0

        events, max_record = self._parse_xml(xml_text, last_record)

        if events:
            self.queue.enqueue_many(events)
            logger.debug("Enqueued %d Windows event(s)", len(events))

        if max_record > last_record:
            self.queue.save_evtlog_record(_LOG_NAME, max_record)

        return len(events)

    def _run_wevtutil(self, xpath: str) -> Optional[str]:
        cmd = [
            "wevtutil", "qe", _LOG_NAME,
            f"/q:{xpath}",
            "/f:xml",
            "/c:200",
            "/rd:false",  # oldest-first so we process in order
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("wevtutil error: %s", exc)
            return None

    def _parse_xml(
        self, xml_text: str, last_record: int
    ) -> tuple:
        # wevtutil returns consecutive <Event> elements without a root wrapper.
        try:
            root = ET.fromstring(f"<Events>{xml_text}</Events>")
        except ET.ParseError as exc:
            logger.warning("Failed to parse wevtutil XML: %s", exc)
            return [], last_record

        events: List[dict] = []
        max_record = last_record

        for event_el in root.findall("e:Event", _NS):
            system = event_el.find("e:System", _NS)
            if system is None:
                continue

            event_id_el = system.find("e:EventID", _NS)
            record_id_el = system.find("e:EventRecordID", _NS)
            time_el = system.find("e:TimeCreated", _NS)
            if event_id_el is None:
                continue

            try:
                event_id = int(_text(event_id_el))
                record_id = int(_text(record_id_el)) if record_id_el is not None else 0
            except (ValueError, TypeError):
                continue

            # Normalize ISO timestamp from the SystemTime attribute
            raw_ts = (
                time_el.get("SystemTime", "") if time_el is not None else ""
            )
            ts = raw_ts.replace("Z", "").split(".")[0] or datetime.utcnow().isoformat()

            event_data = event_el.find("e:EventData", _NS)
            if event_data is None:
                continue

            raw_xml = ET.tostring(event_el, encoding="unicode")
            parsed = self._dispatch(event_id, ts, event_data, raw_xml)
            if parsed:
                events.append(parsed)

            if record_id > max_record:
                max_record = record_id

        return events, max_record

    def _dispatch(
        self, event_id: int, ts: str, data: ET.Element, raw: str
    ) -> Optional[dict]:
        handlers = {
            4625: self._parse_4625,
            4624: self._parse_4624,
            4672: self._parse_4672,
            4663: self._parse_4663,
            5156: self._parse_5156,
        }
        handler = handlers.get(event_id)
        return handler(ts, data, raw) if handler else None

    def _parse_4625(self, ts: str, data: ET.Element, raw: str) -> dict:
        """Failed logon."""
        user = _data(data, "TargetUserName") or "unknown"
        ip = _data(data, "IpAddress") or _data(data, "WorkstationName") or None
        return {
            "timestamp": ts,
            "source": config.SOURCE,
            "event_type": "login_attempt",
            "severity": "medium",
            "user": user,
            "action": "failed",
            "resource": None,
            "details": {"ip": ip, "event_id": 4625, "method": "windows_logon"},
            "raw_log": raw[:2048],
        }

    def _parse_4624(self, ts: str, data: ET.Element, raw: str) -> Optional[dict]:
        """Successful logon — only report network logon types to reduce noise."""
        try:
            logon_type = int(_data(data, "LogonType"))
        except (ValueError, TypeError):
            logon_type = 0

        if logon_type not in _REMOTE_LOGON_TYPES:
            return None

        user = _data(data, "TargetUserName") or "unknown"
        ip = _data(data, "IpAddress") or _data(data, "WorkstationName") or None
        return {
            "timestamp": ts,
            "source": config.SOURCE,
            "event_type": "login_attempt",
            "severity": "low",
            "user": user,
            "action": "success",
            "resource": None,
            "details": {
                "ip": ip,
                "event_id": 4624,
                "logon_type": logon_type,
                "method": "windows_logon",
            },
            "raw_log": raw[:2048],
        }

    def _parse_4672(self, ts: str, data: ET.Element, raw: str) -> dict:
        """Special privileges assigned to new logon."""
        user = _data(data, "SubjectUserName") or "unknown"
        privileges = _data(data, "PrivilegeList")
        return {
            "timestamp": ts,
            "source": config.SOURCE,
            "event_type": "privilege_change",
            "severity": "medium",
            "user": user,
            "action": "elevated",
            "resource": None,
            "details": {
                "event_id": 4672,
                "privileges": privileges,
                "type": "special_logon",
            },
            "raw_log": raw[:2048],
        }

    def _parse_4663(self, ts: str, data: ET.Element, raw: str) -> Optional[dict]:
        """Object access (file/directory read/write)."""
        user = _data(data, "SubjectUserName") or "unknown"
        obj_name = _data(data, "ObjectName")
        if not obj_name:
            return None
        return {
            "timestamp": ts,
            "source": config.SOURCE,
            "event_type": "file_access",
            "severity": "high",
            "user": user,
            "action": "accessed",
            "resource": obj_name,
            "details": {
                "event_id": 4663,
                "object_type": _data(data, "ObjectType"),
            },
            "raw_log": raw[:2048],
        }

    def _parse_5156(self, ts: str, data: ET.Element, raw: str) -> dict:
        """Windows Filtering Platform permitted a network connection."""
        src_ip = _data(data, "SourceAddress")
        dst_ip = _data(data, "DestAddress")
        dst_port_str = _data(data, "DestPort")
        direction = _data(data, "Direction")
        app = _data(data, "Application")
        dst_port = int(dst_port_str) if dst_port_str.isdigit() else None
        return {
            "timestamp": ts,
            "source": config.SOURCE,
            "event_type": "network_connection",
            "severity": "low",
            "user": None,
            "action": "allowed",
            "resource": f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
            "details": {
                "event_id": 5156,
                "ip": src_ip or None,
                "dst_ip": dst_ip or None,
                "dst_port": dst_port,
                "direction": direction,
                "application": app,
            },
            "raw_log": raw[:2048],
        }
