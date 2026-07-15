import logging
import platform
from pathlib import Path
from typing import List

from src.local_queue import LocalQueue
from src.parsers.base import BaseParser

logger = logging.getLogger(__name__)

_IS_LINUX = platform.system() == "Linux"


class FileTailer:
    def __init__(
        self, filepath: str, parser: BaseParser, queue: LocalQueue
    ) -> None:
        self.filepath = filepath
        self.parser = parser
        self.queue = queue

    def poll(self) -> int:
        path = Path(self.filepath)
        if not path.exists():
            return 0

        saved_offset, saved_inode = self.queue.get_file_position(self.filepath)

        try:
            stat = path.stat()
            current_size = stat.st_size
            current_inode = stat.st_ino if _IS_LINUX else None
        except OSError:
            return 0

        # Detect rotation and reset position
        rotated = False
        if _IS_LINUX and saved_inode and current_inode != saved_inode:
            logger.info("Log rotation detected (inode change): %s", self.filepath)
            rotated = True
        elif saved_offset > current_size:
            logger.info("Log rotation detected (size decrease): %s", self.filepath)
            rotated = True

        if rotated:
            saved_offset = 0
            self.queue.save_file_position(self.filepath, 0, current_inode)

        if current_size <= saved_offset:
            return 0  # nothing new to read

        events: List[dict] = []
        new_offset = saved_offset

        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(saved_offset)
                for raw_line in fh:
                    new_offset = fh.tell()
                    line = raw_line.rstrip("\n").rstrip("\r")
                    if not line:
                        continue
                    event = self.parser.parse(line)
                    if event is not None:
                        events.append(event)
        except OSError as exc:
            logger.warning("Could not read %s: %s", self.filepath, exc)
            return 0

        if events:
            self.queue.enqueue_many(events)

        self.queue.save_file_position(self.filepath, new_offset, current_inode)
        return len(events)
