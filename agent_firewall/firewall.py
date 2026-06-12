from typing import List, Optional
from .models import Intent, Policy, ScanResult, DEFAULT_POLICY
from .llm_scanner import LLMScanner
from .exceptions import FirewallBlockedException

class AgentFirewall:
    """The main client for the Agent Firewall."""

    def __init__(self,
                 policy: Optional[Policy] = None,
                 scanner: Optional[LLMScanner] = None,
                 fail_closed: bool = True):
        """
        Initialize the firewall.

        Args:
            policy: A Policy object containing intents. If None, DEFAULT_POLICY is used.
            scanner: An LLMScanner instance. If None, a default one is instantiated.
            fail_closed: If True, blocks on scanner errors. If False, allows on errors.
        """
        import copy
        self.policy = policy if policy is not None else copy.deepcopy(DEFAULT_POLICY)
        self.scanner = scanner if scanner is not None else LLMScanner()
        self.fail_closed = fail_closed

    def add_custom_intent(self, name: str, description: str):
        """Allows developers to quickly add a custom intent to the current policy."""
        self.policy.add_intent(Intent(name=name, description=description))

    def analyze(self, input_data: str) -> ScanResult:
        """
        Analyzes the input data against the active policy.

        Returns:
            ScanResult containing safeness, intent (if any), and reason.
        """
        try:
            return self.scanner.scan(input_text=input_data, intents=self.policy.intents)
        except Exception as e:
            if self.fail_closed:
                # If we fail closed, we treat scanner failures as a block.
                raise FirewallBlockedException(
                    intent="scanner_error",
                    reason=f"The firewall scanner failed and fail_closed is True. Error: {str(e)}"
                )
            else:
                # If we fail open, we log/ignore and return safe.
                return ScanResult(is_safe=True)

    def verify(self, input_data: str):
        """
        Analyzes the input data and raises an exception if a malicious intent is detected.
        Use this for inline checks.
        """
        result = self.analyze(input_data)
        if not result.is_safe:
            raise FirewallBlockedException(
                intent=result.intent_detected or "unknown_malicious_intent",
                reason=result.reason or "No reason provided by scanner."
            )
