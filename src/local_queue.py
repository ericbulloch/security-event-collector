import json
import logging
import sqlite3
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    payload           TEXT    NOT NULL,
    created_at        TEXT    DEFAULT (datetime('now')),
    retry_count       INTEGER DEFAULT 0,
    last_attempted_at TEXT
);

CREATE TABLE IF NOT EXISTS file_positions (
    filepath    TEXT    PRIMARY KEY,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    inode       INTEGER,
    updated_at  TEXT    DEFAULT (datetime('now'))
);
"""


class LocalQueue:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        logger.debug("Local queue database ready: %s", self.db_path)

    # ── Event queue ───────────────────────────────────────────────────────────

    def enqueue_many(self, events: List[dict]) -> None:
        if not events:
            return
        rows = [(json.dumps(e),) for e in events]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO pending_events (payload) VALUES (?)", rows
            )
        logger.debug("Enqueued %d event(s) to local buffer", len(events))

    def get_pending(self, limit: int = 25) -> List[Tuple[int, dict]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, payload FROM pending_events ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [(row["id"], json.loads(row["payload"])) for row in rows]

    def mark_sent(self, ids: List[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM pending_events WHERE id IN ({placeholders})", ids
            )
        logger.debug("Removed %d sent event(s) from local buffer", len(ids))

    def increment_retry(self, ids: List[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._connect() as conn:
            conn.execute(
                f"""UPDATE pending_events
                    SET retry_count = retry_count + 1,
                        last_attempted_at = datetime('now')
                    WHERE id IN ({placeholders})""",
                ids,
            )

    def pending_count(self) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0]

    # ── File positions ────────────────────────────────────────────────────────

    def get_file_position(self, filepath: str) -> Tuple[int, Optional[int]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT byte_offset, inode FROM file_positions WHERE filepath = ?",
                (filepath,),
            ).fetchone()
        return (row["byte_offset"], row["inode"]) if row else (0, None)

    def save_file_position(
        self, filepath: str, byte_offset: int, inode: Optional[int] = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO file_positions (filepath, byte_offset, inode, updated_at)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT(filepath) DO UPDATE SET
                       byte_offset = excluded.byte_offset,
                       inode       = excluded.inode,
                       updated_at  = excluded.updated_at""",
                (filepath, byte_offset, inode),
            )

    # ── Windows Event Log position (reuses file_positions table) ─────────────

    def get_evtlog_record(self, log_name: str) -> int:
        key = f"__evtlog__{log_name}"
        offset, _ = self.get_file_position(key)
        return offset  # byte_offset column reused as record_id

    def save_evtlog_record(self, log_name: str, record_id: int) -> None:
        key = f"__evtlog__{log_name}"
        self.save_file_position(key, record_id, None)
