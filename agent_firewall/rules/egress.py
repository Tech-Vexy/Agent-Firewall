import re
from typing import Any, Optional
from ..models import FirewallRule, RulePhase, RuleAction, RuleResult

class SecretsScannerRule(FirewallRule):
    """
    Scans for and redacts sensitive secrets like AWS keys, JWTs, and private SSH keys
    before they are sent over the network or displayed to the user.
    """
    @property
    def id(self) -> str:
        return "secrets-scanner"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.EGRESS

    @property
    def description(self) -> str:
        return "Redacts secrets such as AWS keys, JWTs, and SSH keys."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        modified_payload = payload
        redacted = False

        # Dictionary of secret patterns
        patterns = {
            "AWS_KEY": re.compile(r'(?i)AKIA[0-9A-Z]{16}'),
            "SSH_PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----'),
            "JWT": re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*')
        }

        for secret_type, pattern in patterns.items():
            if pattern.search(modified_payload):
                redacted = True
                modified_payload = pattern.sub(f"[REDACTED_{secret_type}]", modified_payload)

        if redacted:
            return RuleResult(
                action=RuleAction.REDACT,
                reason="Sensitive secrets detected and redacted.",
                modified_payload=modified_payload
            )

        return RuleResult(action=RuleAction.ALLOW)


class PIIRedactorRule(FirewallRule):
    """
    Scans for and masks Personally Identifiable Information like SSNs and Credit Cards.
    """
    @property
    def id(self) -> str:
        return "pii-redactor"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.EGRESS

    @property
    def description(self) -> str:
        return "Redacts PII such as Social Security Numbers and Credit Cards."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        modified_payload = payload
        redacted = False

        # Basic PII patterns
        patterns = {
            "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            # Basic credit card pattern (13-19 digits, optionally separated by space or dash)
            "CREDIT_CARD": re.compile(r'\b(?:\d[ -]*?){13,16}\b')
        }

        for pii_type, pattern in patterns.items():
            if pattern.search(modified_payload):
                redacted = True
                modified_payload = pattern.sub(f"[REDACTED_{pii_type}]", modified_payload)

        if redacted:
            return RuleResult(
                action=RuleAction.REDACT,
                reason="PII detected and redacted.",
                modified_payload=modified_payload
            )

        return RuleResult(action=RuleAction.ALLOW)
