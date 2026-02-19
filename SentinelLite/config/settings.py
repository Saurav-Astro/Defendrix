import os
from pathlib import Path


def _load_env():
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_env()

DEFAULT_TIMEOUT = 5
VERIFY_SSL = False

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'",
    "\" OR \"1\"=\"1\"--",
]

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "odbc",
    "database error",
    "sqlite",
    "psql",
    "postgres",
]

LENGTH_DELTA_THRESHOLD = 120

XSS_PAYLOADS = ["<svg/onload=alert(1)>"]

REQUIRED_HEADERS = {
    "X-Frame-Options": "Prevents clickjacking attacks",
    "Content-Security-Policy": "Prevents injection attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
}
