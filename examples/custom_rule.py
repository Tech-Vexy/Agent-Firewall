"""
Example: Creating and Injecting a Custom Firewall Rule
======================================================
This example demonstrates how to subclass `FirewallRule` to create
custom business logic. In this case, we create an EGRESS rule that
prevents the agent from recommending competitor products.
"""

import os
from typing import Any, Optional

from agent_firewall import (
    AgentFirewall,
    FirewallRule,
    RulePhase,
    RuleAction,
    RuleResult,
    FirewallBlockedException
)

# 1. Define the Custom Rule
class PreventCompetitorMentionsRule(FirewallRule):
    @property
    def id(self) -> str:
        return "prevent-competitor-mentions"

    @property
    def phase(self) -> RulePhase:
        # We apply this to the final output (Egress)
        return RulePhase.EGRESS

    @property
    def description(self) -> str:
        return "Blocks the agent from mentioning or recommending competitor products."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            # If the payload isn't a string (e.g. it's a structured object we don't handle), allow it.
            return RuleResult(action=RuleAction.ALLOW)

        competitors = ["AcmeCorp", "EvilGeniusesInc"]

        # Simple string matching (can be expanded to regex or NLP)
        for competitor in competitors:
            if competitor.lower() in payload.lower():
                return RuleResult(
                    action=RuleAction.BLOCK,
                    reason=f"Agent attempted to mention competitor: {competitor}"
                )

        return RuleResult(action=RuleAction.ALLOW)

# 2. Initialize the Firewall with the Custom Rule

# For the example to run without an OpenAI key, we provide a dummy scanner
from agent_firewall.llm_scanner import LLMScanner
scanner_kwargs = {}
if "OPENAI_API_KEY" not in os.environ:
    scanner_kwargs["api_key"] = "dummy_key_for_testing"

firewall = AgentFirewall(
    rules=[
        PreventCompetitorMentionsRule()
    ],
    scanner=LLMScanner(**scanner_kwargs),
    fail_closed=True if "OPENAI_API_KEY" in os.environ else False
)

print("--- Initialized Agent Firewall with Custom Rule ---")


# 3. Test the Rule

if __name__ == "__main__":

    # Simulate an agent generating a response
    safe_response = "I highly recommend our in-house analytics tool for your needs!"
    competitor_response = "You might want to check out AcmeCorp's analytics platform, it's very popular."

    print("\n[Test 1] Safe Output:")
    try:
        firewall.evaluate_egress(safe_response)
        print("Output is safe. Delivering to user...")
    except FirewallBlockedException as e:
        print(f"Blocked! {e.reason}")

    print("\n[Test 2] Competitor Mention Output:")
    try:
        firewall.evaluate_egress(competitor_response)
        print("Output is safe. Delivering to user...")
    except FirewallBlockedException as e:
        print(f"🔥 Firewall Blocked Output! Intent: {e.intent}. Reason: {e.reason}")
