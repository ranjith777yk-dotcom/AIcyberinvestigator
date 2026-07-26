"""Environment-driven production concurrency and graceful lifecycle settings."""

import os


def positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


bind = f"0.0.0.0:{positive_int('PORT', 8000)}"
workers = positive_int("WEB_WORKERS", 2)
threads = positive_int("WEB_THREADS", 4)
worker_class = "gthread"
timeout = positive_int("WEB_REQUEST_TIMEOUT_SECONDS", 120)
graceful_timeout = positive_int("WEB_GRACEFUL_TIMEOUT_SECONDS", 30)
keepalive = positive_int("WEB_KEEPALIVE_SECONDS", 5)
max_requests = positive_int("WEB_MAX_REQUESTS", 2000)
max_requests_jitter = positive_int("WEB_MAX_REQUESTS_JITTER", 200)
accesslog = "-"
errorlog = "-"
capture_output = True
