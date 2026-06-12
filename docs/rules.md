# Rules Architecture

To make the SDK scalable, we use a **modular rules engine**. This allows developers to mix, match, and inject custom rules based on their specific agent's risk profile.

A robust firewall evaluates rules across three distinct phases:

1. **INGRESS:** What the user says (protects the model).
2. **TOOL_CALL:** What the agent attempts to do (protects the infrastructure).
3. **EGRESS:** What the agent sends back (protects the data).

## Built-in Rules

The SDK comes with several highly-tuned rules out-of-the-box.

### Ingress Rules
- `PromptInjectionRule`: Blocks heuristic prompt injections like "ignore all previous instructions".
- `EncodingDenylistRule`: Blocks inputs containing excessive Base64, Hex, or Unicode-escaped strings used to bypass semantic filters.
- `ContextBoundaryRule`: Prevents tag breakout attacks (e.g., injecting `</user_input>`).

### Runtime (Tool Call) Rules
- `DestructiveCommandRule`: Blocks shell commands like `rm -rf`, `mkfs`, or `wget` using Regex.
- `NetworkAllowlistRule`: Restricts HTTP/Fetch tools to a specific list of domains.
- `FileSystemJailRule`: Enforces a strict directory path for file read/write tools, preventing directory traversal attacks.

### Egress Rules
- `SecretsScannerRule`: Scans for and **redacts** AWS keys, JWTs, and private SSH keys.
- `PIIRedactorRule`: Scans for and **redacts** Personally Identifiable Information like SSNs and Credit Cards.

## Writing a Custom Rule

You can easily write custom rules for your specific business logic by extending the `FirewallRule` abstract base class.

Every rule must return a `RuleResult` with an action of `ALLOW`, `BLOCK`, `REDACT`, or `FLAG`.

```python
from agent_firewall.models import FirewallRule, RulePhase, RuleAction, RuleResult
from typing import Any, Optional

class PreventCompetitorMentionsRule(FirewallRule):
    @property
    def id(self) -> str:
        return "prevent-competitor-mentions"

    @property
    def phase(self) -> RulePhase:
        # We apply this to the final output
        return RulePhase.EGRESS

    @property
    def description(self) -> str:
        return "Blocks the agent from recommending competitor products."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, str):
            return RuleResult(action=RuleAction.ALLOW)

        competitors = ["AcmeCorp", "EvilGeniusesInc"]

        for competitor in competitors:
            if competitor.lower() in payload.lower():
                return RuleResult(
                    action=RuleAction.BLOCK,
                    reason=f"Agent attempted to mention competitor: {competitor}"
                )

        return RuleResult(action=RuleAction.ALLOW)
```

To use it, just add it to your firewall initialization:

```python
firewall = AgentFirewall(
    rules=[
        PIIRedactorRule(),
        PreventCompetitorMentionsRule()
    ]
)
```
