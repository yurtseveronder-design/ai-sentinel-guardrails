"""
Advanced guardrail detection plugins for PII, Secrets, and Injection.
"""

import re

class PIIDetectorPlugin:
    EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    PHONE_REGEX = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')

    @staticmethod
    def evaluate(text: str) -> dict:
        found_pii = []
        if PIIDetectorPlugin.EMAIL_REGEX.search(text):
            found_pii.append("email")
        if PIIDetectorPlugin.PHONE_REGEX.search(text):
            found_pii.append("phone_number")
        
        if found_pii:
            return {"blocked": True, "reason": f"PII detected: {', '.join(found_pii)}"}
        return {"blocked": False, "reason": None}


class SecretDetectorPlugin:
    # Updated regex supporting modern token prefixes (sk-, sk-proj-, AKIA, ghp_, etc.) with hyphens and alphanumeric characters
    API_KEY_REGEX = re.compile(r'\b(sk-[a-zA-Z0-9\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b')

    @staticmethod
    def evaluate(text: str) -> dict:
        if SecretDetectorPlugin.API_KEY_REGEX.search(text):
            return {"blocked": True, "reason": "Secret or API key detected in input."}
        return {"blocked": False, "reason": None}