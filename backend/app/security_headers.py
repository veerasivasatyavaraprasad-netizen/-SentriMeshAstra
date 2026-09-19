"""Standard defensive response headers, applied to every response.

Small and boring on purpose — these are the headers any API serving a
browser-based console should send regardless of what else is deployed in
front of it (a CDN/WAF may add more; this is the floor, not the ceiling).
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    # Conservative baseline permissions policy — this API doesn't need
    # camera/mic/geolocation from anything rendering it.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response
