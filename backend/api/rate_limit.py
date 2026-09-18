"""
Lightweight rate limiting middleware -- real gap identified via security
review: no request throttling existed at all, leaving upload/analyze
endpoints (the most resource-intensive ones) open to trivial flooding.

Deliberately simple (in-memory sliding window, no external dependency like
Redis) given this project's documented scope: a single-user academic
deployment, not a multi-tenant production service. If this platform is
ever deployed for concurrent multi-user access, this in-memory approach
won't scale across multiple worker processes and should be replaced with
a shared store (Redis) -- noted here rather than silently left as a latent
limitation.

RATE_LIMIT_ENABLED / RATE_LIMIT_MAX_REQUESTS / RATE_LIMIT_WINDOW_SECONDS are
module-level (not hardcoded inside the class) specifically so tests can
monkeypatch them directly, the same pattern used elsewhere in this codebase
(e.g. acquisition.service.MAX_VALID_SIZE_BYTES) -- necessary here because
the in-memory request log is a module-level global that would otherwise
persist and accumulate across every test in a single pytest run (since
Python caches the module import), causing unrelated tests to start
failing once enough requests had been made across the whole test session.
"""
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

RATE_LIMIT_ENABLED = True
RATE_LIMIT_MAX_REQUESTS = 120
RATE_LIMIT_WINDOW_SECONDS = 60

# Tighter limits for the two most expensive operations: an upload writes to
# disk (and now hashes the whole file), and analyze runs the entire
# Volatility pipeline -- both are far more expensive per-request than a
# simple GET, so they get their own, stricter budget in addition to the
# global one above.
EXPENSIVE_PATH_SUFFIXES = ("/upload", "/analyze")
RATE_LIMIT_EXPENSIVE_MAX_REQUESTS = 10
RATE_LIMIT_EXPENSIVE_WINDOW_SECONDS = 60

_request_log: dict = defaultdict(deque)
_expensive_request_log: dict = defaultdict(deque)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _prune_and_check(log: deque, now: float, window: float, limit: int) -> bool:
    """Drop timestamps outside the window, then check if the limit is exceeded. Returns True if allowed."""
    while log and now - log[0] > window:
        log.popleft()
    return len(log) < limit


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not RATE_LIMIT_ENABLED:
            return await call_next(request)

        client_key = _client_key(request)
        now = time.monotonic()

        if request.url.path.endswith(EXPENSIVE_PATH_SUFFIXES):
            expensive_log = _expensive_request_log[client_key]
            if not _prune_and_check(expensive_log, now, RATE_LIMIT_EXPENSIVE_WINDOW_SECONDS, RATE_LIMIT_EXPENSIVE_MAX_REQUESTS):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded for this operation. Please wait before retrying."},
                )
            expensive_log.append(now)

        general_log = _request_log[client_key]
        if not _prune_and_check(general_log, now, RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down and try again shortly."},
            )
        general_log.append(now)

        return await call_next(request)
