import logging
from typing import List, Tuple

import requests

import src.config as config
from src.local_queue import LocalQueue

logger = logging.getLogger(__name__)


class Sender:
    def __init__(self, queue: LocalQueue) -> None:
        self.queue = queue
        self._session = self._make_session()

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.headers["X-API-Key"] = config.API_KEY
        session.headers["Content-Type"] = "application/json"
        return session

    def flush(self) -> int:
        pending = self.queue.get_pending(limit=config.BATCH_SIZE)
        if not pending:
            return 0

        sent_ids: List[int] = []
        failed_ids: List[int] = []
        stop = False

        for event_id, event in pending:
            if stop:
                # Don't attempt remaining events — leave them for next cycle.
                failed_ids.append(event_id)
                continue

            try:
                resp = self._session.post(
                    f"{config.API_URL}/v1/events",
                    json=event,
                    timeout=config.REQUEST_TIMEOUT,
                )

                if resp.status_code in (200, 201, 202):
                    sent_ids.append(event_id)
                elif resp.status_code == 429:
                    logger.warning("Rate-limited by correlator API; backing off this cycle")
                    failed_ids.append(event_id)
                    stop = True
                elif resp.status_code == 401:
                    logger.error(
                        "API key rejected (HTTP 401) — check COLLECTOR_API_KEY in .env"
                    )
                    failed_ids.append(event_id)
                    stop = True
                else:
                    logger.warning(
                        "API returned HTTP %d for event %d; keeping buffered",
                        resp.status_code,
                        event_id,
                    )
                    failed_ids.append(event_id)

            except requests.exceptions.ConnectionError:
                logger.info(
                    "Correlator API unreachable — %d event(s) will stay buffered",
                    len(pending) - len(sent_ids),
                )
                failed_ids.append(event_id)
                stop = True
            except requests.exceptions.Timeout:
                logger.warning(
                    "Request timed out after %ds — events will stay buffered",
                    config.REQUEST_TIMEOUT,
                )
                failed_ids.append(event_id)
                stop = True

        self.queue.mark_sent(sent_ids)
        if failed_ids:
            self.queue.increment_retry(failed_ids)

        if sent_ids:
            logger.info("Flushed %d event(s) to correlator", len(sent_ids))

        buffered = self.queue.pending_count()
        if buffered:
            logger.debug("%d event(s) still buffered locally", buffered)

        return len(sent_ids)
