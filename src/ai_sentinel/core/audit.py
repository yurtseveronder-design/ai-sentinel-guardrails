"""
Structured audit logging module for AI-Sentinel Guardrails.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("ai_sentinel.audit")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class AuditLogger:
    @staticmethod
    def log_event(event_type: str, payload: str, details: dict):
        """
        Logs structured security events in JSON format.
        """
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload_snippet": payload[:100] if payload else "",
            "details": details
        }
        logger.info(json.dumps(record))