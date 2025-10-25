"""
IP Anonymization Middleware for FastAPI
Replaces client IP addresses with hashed versions to protect privacy in logs
"""
import hashlib
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class IPAnonymizerMiddleware(BaseHTTPMiddleware):
    """Middleware that anonymizes IP addresses in requests"""

    async def dispatch(self, request: Request, call_next):
        # Get the original client IP
        client_host = request.client.host if request.client else "unknown"

        # Hash the IP address
        if client_host != "unknown":
            hashed_ip = hashlib.sha256(client_host.encode()).hexdigest()[:12]
            # Override the client with anonymized version
            # Note: This modifies the request scope which affects logging
            request.scope["client"] = (f"user-{hashed_ip}", request.client.port if request.client else 0)

        response = await call_next(request)
        return response
