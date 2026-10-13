"""Keep long file transfers alive, including when Railway overrides Procfile."""
import os

worker_class = "gthread"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
threads = int(os.getenv("GUNICORN_THREADS", "8"))
# gthread heartbeats while requests run: this is a worker liveness timeout,
# not a maximum upload/download duration.
timeout = 600
graceful_timeout = 600
keepalive = 5
