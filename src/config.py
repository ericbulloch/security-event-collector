import os
import socket

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional; set env vars directly if preferred

# ── Required ──────────────────────────────────────────────────────────────────
# URL of the security-event-correlator ingestion API (no trailing slash).
API_URL: str = os.getenv("COLLECTOR_API_URL", "http://localhost:8000").rstrip("/")

# API key issued by the correlator's seed script.
API_KEY: str = os.getenv("COLLECTOR_API_KEY", "")

# ── Source identification ──────────────────────────────────────────────────────
# The value placed in the 'source' field of every event.  Defaults to the
# machine hostname so events from multiple collectors are attributed correctly.
SOURCE: str = os.getenv("COLLECTOR_SOURCE", socket.gethostname())

# ── Tuning ────────────────────────────────────────────────────────────────────
POLL_INTERVAL: int = int(os.getenv("COLLECTOR_POLL_INTERVAL", "2"))       # seconds between cycles
BATCH_SIZE: int = int(os.getenv("COLLECTOR_BATCH_SIZE", "25"))             # events per flush pass
REQUEST_TIMEOUT: int = int(os.getenv("COLLECTOR_REQUEST_TIMEOUT", "10"))  # per-request timeout (s)

# ── Local buffer ──────────────────────────────────────────────────────────────
# Path to the SQLite database used to buffer events when the API is unreachable.
DB_PATH: str = os.getenv("COLLECTOR_DB_PATH", "collector.db")

# ── Linux log paths ───────────────────────────────────────────────────────────
AUTH_LOG: str = os.getenv("COLLECTOR_AUTH_LOG", "/var/log/auth.log")
UFW_LOG: str = os.getenv("COLLECTOR_UFW_LOG", "/var/log/ufw.log")
AUDIT_LOG: str = os.getenv("COLLECTOR_AUDIT_LOG", "/var/log/audit/audit.log")

# ── Windows log paths ─────────────────────────────────────────────────────────
WINDOWS_FIREWALL_LOG: str = os.getenv(
    "COLLECTOR_WINDOWS_FIREWALL_LOG",
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
)
