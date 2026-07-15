"""
Security Event Collector — entry point.

Usage:
    python main.py

All configuration is read from environment variables (loaded from .env if
present in the working directory).  See .env.example for the full list.
"""
import logging
import os

from src.collector import Collector


def _setup_logging() -> None:
    level = getattr(
        logging,
        os.getenv("COLLECTOR_LOG_LEVEL", "INFO").upper(),
        logging.INFO,
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


if __name__ == "__main__":
    _setup_logging()
    Collector().run()
