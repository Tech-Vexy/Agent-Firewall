from pydantic import BaseModel, Field
from typing import List, Any, Optional
from enum import Enum
import abc

class Intent(BaseModel):
    """Represents a category of behavior or goal, often malicious, that the firewall should monitor."""
    name: str = Field(..., description="The name of the intent, e.g., 'prompt_injection'")
    description: str = Field(..., description="A detailed description of the intent to help the LLM scanner classify correctly.")

class ScanResult(BaseModel):
    """The result of an LLM scan of input/code."""
    is_safe: bool = Field(..., description="True if the input is safe, False if a malicious intent or predictive threat was detected.")
    intent_detected: str | None = Field(None, description="The name of the detected malicious intent, if any.")
    is_predictive_threat: bool = Field(False, description="True if the input is flagged as a zero-day or multi-step predictive anomaly.")
    risk_score: float | None = Field(None, description="A score from 0.0 to 1.0 indicating the likelihood of a threat based on context and history.")
    reason: str | None = Field(None, description="The reason provided by the scanner for the detection.")

class SessionMemory(BaseModel):
    """Maintains a history of inputs and their scan results for predictive analysis."""
    session_id: str
    history: List[dict] = Field(default_factory=list, description="A list containing previous inputs and their scan results.")

    def add_record(self, input_data: str, result: ScanResult):
        self.history.append({"input": input_data, "result": result.model_dump()})
        # Prevent unbound memory growth by keeping only last 10 interactions
        if len(self.history) > 10:
            self.history = self.history[-10:]

class RuleAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    FLAG = "FLAG"

class RulePhase(str, Enum):
    INGRESS = "INGRESS"
    TOOL_CALL = "TOOL_CALL"
    EGRESS = "EGRESS"

class RuleResult(BaseModel):
    action: RuleAction
    reason: Optional[str] = None
    modified_payload: Optional[Any] = None

class FirewallRule(abc.ABC):
    @property
    @abc.abstractmethod
    def id(self) -> str:
        pass

    @property
    @abc.abstractmethod
    def phase(self) -> RulePhase:
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        pass

    @abc.abstractmethod
    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        pass


class Policy(BaseModel):
    """A collection of intents that a firewall instance uses to scan."""
    intents: List[Intent] = Field(default_factory=list, description="List of intents monitored by this policy.")

    def add_intent(self, intent: Intent):
        self.intents.append(intent)

BUILTIN_INTENTS = [
    Intent(
        name="prompt_injection",
        description="An attempt to override, bypass, or alter the system's core instructions, constraints, or guardrails using manipulative phrasing."
    ),
    Intent(
        name="unauthorized_code_execution",
        description="An attempt to execute arbitrary, unauthorized, or potentially destructive system commands or code snippets."
    ),
    Intent(
        name="data_exfiltration",
        description="An attempt to extract or leak sensitive, confidential, or proprietary information (e.g., PII, API keys, passwords)."
    ),
    Intent(
        name="jailbreak",
        description="An attempt to bypass safety filters or policies to generate harmful, illegal, or unethical content, often via roleplay or hypotheticals."
    )
]

DEFAULT_POLICY = Policy(intents=BUILTIN_INTENTS)
