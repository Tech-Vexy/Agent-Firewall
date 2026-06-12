from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

# Import from our SDK
from agent_firewall import (
    AgentFirewall,
    PromptInjectionRule,
    EncodingDenylistRule,
    ContextBoundaryRule,
    DestructiveCommandRule,
    NetworkAllowlistRule,
    FileSystemJailRule,
    SecretsScannerRule,
    PIIRedactorRule,
    FirewallBlockedException
)

app = FastAPI(
    title="Agent Firewall as a Service",
    description="A centralized firewall API to protect AI agents across your organization.",
    version="1.0.0"
)

import os

# Initialize the global Firewall instance with our standard built-in rules.
# In a real production deployment, this might load rules from a DB or YAML config.

# For testing environments, allow a dummy LLM scanner initialization
from agent_firewall.llm_scanner import LLMScanner

scanner_kwargs = {}
if "OPENAI_API_KEY" not in os.environ:
    scanner_kwargs["api_key"] = "dummy_key_for_testing"

firewall = AgentFirewall(
    rules=[
        # Ingress
        PromptInjectionRule(),
        EncodingDenylistRule(),
        ContextBoundaryRule(),
        # Runtime (Tool calls)
        DestructiveCommandRule(),
        NetworkAllowlistRule(allowed_domains=["github.com", "api.internal.com"]),
        FileSystemJailRule(allowed_base_dir="/tmp/agent_sandbox"),
        # Egress
        SecretsScannerRule(),
        PIIRedactorRule()
    ],
    scanner=LLMScanner(**scanner_kwargs),
    # The LLMScanner requires an OPENAI_API_KEY environment variable.
    # Set fail_closed=False if you want the API to continue even if OpenAI fails.
    fail_closed=True
)

from fastapi.responses import JSONResponse

# Exception handler for when the firewall blocks an action
@app.exception_handler(FirewallBlockedException)
async def firewall_blocked_exception_handler(request: Request, exc: FirewallBlockedException):
    return JSONResponse(
        status_code=403,
        content={"detail": {"intent": exc.intent, "reason": exc.reason}},
    )

# --- Models ---

class IngressRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

class IngressResponse(BaseModel):
    action: str
    message: str

class ToolCallRequest(BaseModel):
    tool_name: str
    args: Dict[str, Any]
    session_id: Optional[str] = None

class ToolCallResponse(BaseModel):
    action: str
    message: str

class EgressRequest(BaseModel):
    payload: str
    session_id: Optional[str] = None

class EgressResponse(BaseModel):
    action: str
    modified_payload: str

# --- Endpoints ---

@app.post("/scan/ingress", response_model=IngressResponse)
async def scan_ingress(request: IngressRequest):
    """
    Scans a user prompt before it reaches the AI agent.
    Evaluates modular ingress rules followed by the LLM predictive scanner.
    Raises a 403 Forbidden if a threat is detected.
    """
    # Run the full analyzer which includes Ingress rules, LLM intent, and predictive scanning
    # If blocked, the global exception handler will catch FirewallBlockedException
    firewall.verify(request.prompt, session_id=request.session_id)
    return IngressResponse(action="ALLOW", message="Prompt is safe.")

@app.post("/scan/tool", response_model=ToolCallResponse)
async def scan_tool(request: ToolCallRequest):
    """
    Scans a tool execution request (e.g., shell command, network fetch).
    Raises a 403 Forbidden if the action is deemed destructive or unauthorized.
    """
    # If blocked, the global exception handler will catch FirewallBlockedException
    firewall.evaluate_tool_call(request.tool_name, request.args)
    return ToolCallResponse(action="ALLOW", message="Tool execution is safe.")

@app.post("/scan/egress", response_model=EgressResponse)
async def scan_egress(request: EgressRequest):
    """
    Scans the final output from the AI agent before returning it to the user.
    Redacts PII and secrets.
    """
    # If blocked, the global exception handler will catch FirewallBlockedException
    modified_payload = firewall.evaluate_egress(request.payload)
    return EgressResponse(
        action="ALLOW",
        modified_payload=modified_payload
    )

@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "healthy"}
