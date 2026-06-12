class FirewallException(Exception):
    """Base exception for all agent firewall errors."""
    pass

class FirewallBlockedException(FirewallException):
    """Raised when the firewall detects a malicious intent and blocks the execution."""
    def __init__(self, intent: str, reason: str):
        self.intent = intent
        self.reason = reason
        super().__init__(f"Blocked due to malicious intent '{intent}': {reason}")
