from typing import List, Optional, Callable, Dict
from .models import Intent, Policy, ScanResult, DEFAULT_POLICY, SessionMemory
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
        self.sessions: Dict[str, SessionMemory] = {}
        self.on_threat_detected: Optional[Callable[[ScanResult, str], None]] = None

    def set_threat_reporter(self, callback: Callable[[ScanResult, str], None]):
        """Sets a callback that is fired when any threat is detected before blocking."""
        self.on_threat_detected = callback

    def add_custom_intent(self, name: str, description: str):
        """Allows developers to quickly add a custom intent to the current policy."""
        self.policy.add_intent(Intent(name=name, description=description))

    def _get_or_create_session(self, session_id: str) -> SessionMemory:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionMemory(session_id=session_id)
        return self.sessions[session_id]

    def analyze(self, input_data: str, session_id: Optional[str] = None) -> ScanResult:
        """
        Analyzes the input data against the active policy, optionally using session history.

        Returns:
            ScanResult containing safeness, intent (if any), predictive flags, and reason.
        """
        history = None
        session = None
        if session_id:
            session = self._get_or_create_session(session_id)
            history = session.history

        try:
            result = self.scanner.scan(
                input_text=input_data,
                intents=self.policy.intents,
                history=history
            )

            # Record the result in memory if a session is provided
            if session:
                session.add_record(input_data, result)

            # Fire reporting callback if a threat is detected
            if not result.is_safe and self.on_threat_detected:
                self.on_threat_detected(result, input_data)

            return result

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

    def verify(self, input_data: str, session_id: Optional[str] = None):
        """
        Analyzes the input data and raises an exception if a malicious intent or predictive threat is detected.
        Use this for inline checks.
        """
        result = self.analyze(input_data, session_id=session_id)
        if not result.is_safe:
            intent_name = result.intent_detected
            if result.is_predictive_threat:
                intent_name = "predictive_threat"

            raise FirewallBlockedException(
                intent=intent_name or "unknown_malicious_intent",
                reason=result.reason or "No reason provided by scanner."
            )
