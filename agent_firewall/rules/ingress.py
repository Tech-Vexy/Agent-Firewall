import re
from typing import Any, Optional
from ..models import FirewallRule, RulePhase, RuleAction, RuleResult

class PromptInjectionRule(FirewallRule):
    """
    A lightweight heuristic rule to catch basic prompt injections before the LLM scanner.
    """
    @property
    def id(self) -> str:
        return "heuristic-prompt-injection"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.INGRESS

    @property
    def description(self) -> str:
        return "Blocks common prompt injection phrases using heuristics."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        text = payload.lower()
        dangerous_phrases = [
            "ignore all previous instructions",
            "system prompt override",
            "developer mode",
            "you are now dan"
        ]

        for phrase in dangerous_phrases:
            if phrase in text:
                return RuleResult(
                    action=RuleAction.BLOCK,
                    reason=f"Matched prompt injection heuristic: '{phrase}'"
                )

        return RuleResult(action=RuleAction.ALLOW)


class EncodingDenylistRule(FirewallRule):
    """
    Blocks inputs containing excessive Base64, Hex, or Unicode-escaped strings.
    """
    @property
    def id(self) -> str:
        return "encoding-denylist"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.INGRESS

    @property
    def description(self) -> str:
        return "Blocks inputs with suspicious encoding to prevent bypasses."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        # Check for excessive hex (\x41) or unicode (\u0041) escapes
        hex_unicode_pattern = re.compile(r'(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})')
        matches = hex_unicode_pattern.findall(payload)

        if len(matches) > 5:
            return RuleResult(action=RuleAction.BLOCK, reason="Excessive hex/unicode encoding detected.")

        # Basic check for large base64-like strings (just a heuristic)
        base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        if base64_pattern.search(payload):
            return RuleResult(action=RuleAction.BLOCK, reason="Suspicious Base64-like string detected.")

        return RuleResult(action=RuleAction.ALLOW)


class ContextBoundaryRule(FirewallRule):
    """
    Scans the input to ensure the user hasn't injected closing tags (e.g., </user_input>)
    to break out of the context window.
    """
    @property
    def id(self) -> str:
        return "context-boundary-enforcement"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.INGRESS

    @property
    def description(self) -> str:
        return "Prevents tag breakout attacks."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        # Attackers often try to close tags like </user_input>, </text>, etc.
        breakout_pattern = re.compile(r'</[a-zA-Z0-9_]+>')

        if breakout_pattern.search(payload):
            return RuleResult(action=RuleAction.BLOCK, reason="Detected attempt to inject closing XML/HTML tags.")

        return RuleResult(action=RuleAction.ALLOW)
