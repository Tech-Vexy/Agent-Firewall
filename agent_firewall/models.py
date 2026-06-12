from pydantic import BaseModel, Field
from typing import List

class Intent(BaseModel):
    """Represents a category of behavior or goal, often malicious, that the firewall should monitor."""
    name: str = Field(..., description="The name of the intent, e.g., 'prompt_injection'")
    description: str = Field(..., description="A detailed description of the intent to help the LLM scanner classify correctly.")

class ScanResult(BaseModel):
    """The result of an LLM scan of input/code."""
    is_safe: bool = Field(..., description="True if the input is safe, False if a malicious intent was detected.")
    intent_detected: str | None = Field(None, description="The name of the detected malicious intent, if any.")
    reason: str | None = Field(None, description="The reason provided by the scanner for the detection.")

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
