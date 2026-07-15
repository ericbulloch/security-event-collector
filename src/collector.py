import logging
import platform
import sys
import time
from pathlib import Path
from typing import List

import src.config as config
from src.file_tailer import FileTailer
from src.local_queue import LocalQueue
from src.parsers.auth_log import AuthLogParser
from src.parsers.audit_log import AuditLogParser
from src.parsers.ufw_log import UfwLogParser
from src.sender import Sender

logger = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"


class Collector:
    def __init__(self) -> None:
        self.queue = LocalQueue(config.DB_PATH)
        self.sender = Sender(self.queue)
        self.tailers: List[FileTailer] = []
        self.windows_poller = None

        if _IS_LINUX:
            self._setup_linux_tailers()
        elif _IS_WINDOWS:
            self._setup_windows_tailers()
        else:
            logger.warning(
                "Platform '%s' is not explicitly supported; "
                "only Windows and Linux tailers are available.",
                platform.system(),
            )

    def _setup_linux_tailers(self) -> None:
        candidates = [
            (config.AUTH_LOG, AuthLogParser()),
            (config.UFW_LOG, UfwLogParser()),
            (config.AUDIT_LOG, AuditLogParser()),
        ]
        for path, parser in candidates:
            if Path(path).exists():
                self.tailers.append(FileTailer(path, parser, self.queue))
                logger.info("Watching: %s", path)
            else:
                logger.info("Log file not found, skipping: %s", path)

    def _setup_windows_tailers(self) -> None:
        from src.parsers.windows_evtlog import WindowsEventLogPoller
        from src.parsers.windows_firewall import WindowsFirewallLogParser

        self.windows_poller = WindowsEventLogPoller(self.queue)
        logger.info("Watching: Windows Security Event Log")

        fw_log = config.WINDOWS_FIREWALL_LOG
        if Path(fw_log).exists():
            self.tailers.append(
                FileTailer(fw_log, WindowsFirewallLogParser(), self.queue)
            )
            logger.info("Watching: %s", fw_log)
        else:
            logger.info(
                "Windows Firewall log not found at %s — "
                "enable it with: netsh advfirewall set allprofiles logging "
                "droppedconnections enable",
                fw_log,
            )

    def run_once(self) -> None:
        new_events = 0

        for tailer in self.tailers:
            new_events += tailer.poll()

        if self.windows_poller:
            new_events += self.windows_poller.poll()

        sent = self.sender.flush()

        if new_events or sent:
            logger.debug(
                "Cycle complete: %d new event(s) collected, %d sent",
                new_events,
                sent,
            )

    def run(self) -> None:
        if not config.API_KEY:
            logger.error(
                "COLLECTOR_API_KEY is not set — events will buffer locally "
                "but cannot be sent. Set the key in .env and restart."
            )

        logger.info(
            "Collector started  source=%s  api=%s  poll=%ds",
            config.SOURCE,
            config.API_URL,
            config.POLL_INTERVAL,
        )

        buffered = self.queue.pending_count()
        if buffered:
            logger.info(
                "%d event(s) already in local buffer from a previous run", buffered
            )

        try:
            while True:
                self.run_once()
                time.sleep(config.POLL_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Collector stopped")
        except Exception:
            logger.exception("Unexpected error in collector main loop")
            sys.exit(1)
