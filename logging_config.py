"""
Custom logging configuration for uvicorn that anonymizes IP addresses.
"""
import hashlib
import logging
import sys
from typing import Any, Dict


class IPAnonymizingFilter(logging.Filter):
    """Filter that anonymizes IP addresses in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Anonymize IP addresses by hashing them."""
        # uvicorn stores client info in the record
        if hasattr(record, 'client_addr'):
            # Hash the IP address
            ip = record.client_addr[0] if isinstance(record.client_addr, tuple) else record.client_addr
            hashed = hashlib.sha256(ip.encode()).hexdigest()[:12]
            record.client_addr = (f"user-{hashed}", record.client_addr[1] if isinstance(record.client_addr, tuple) and len(record.client_addr) > 1 else 0)

        # Also check the message itself for IP addresses in the format "IP:PORT - "
        if hasattr(record, 'msg'):
            msg = str(record.msg)
            # Look for pattern like "172.18.0.2:59452 - "
            import re
            def anonymize_ip(match):
                ip = match.group(1)
                hashed = hashlib.sha256(ip.encode()).hexdigest()[:12]
                port = match.group(2)
                return f"user-{hashed}:{port} - "

            record.msg = re.sub(r'(\d+\.\d+\.\d+\.\d+):(\d+) - ', anonymize_ip, msg)

        return True


class IPRemovingFilter(logging.Filter):
    """Filter that completely removes IP addresses from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Remove IP addresses from logs."""
        if hasattr(record, 'client_addr'):
            record.client_addr = ("***", 0)

        # Also check the message itself
        if hasattr(record, 'msg'):
            msg = str(record.msg)
            import re
            # Replace IP:PORT with asterisks
            record.msg = re.sub(r'\d+\.\d+\.\d+\.\d+:\d+', '***:***', msg)

        return True


LOGGING_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "anonymize_ip": {
            "()": IPAnonymizingFilter,
        },
        "remove_ip": {
            "()": IPRemovingFilter,
        },
    },
    "formatters": {
        "default": {
            "format": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "format": '%(levelprefix)s %(message)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "filters": ["anonymize_ip"],  # Change to "remove_ip" to completely remove IPs
        },
    },
    "loggers": {
        "uvicorn": {
            "handlers": ["default"],
            "level": "INFO",
        },
        "uvicorn.error": {
            "level": "INFO",
        },
        "uvicorn.access": {
            "handlers": ["access"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
