import re
import os
from typing import Any, Optional, List
from ..models import FirewallRule, RulePhase, RuleAction, RuleResult

class DestructiveCommandRule(FirewallRule):
    """
    Prevents the execution of dangerous shell commands.
    """
    @property
    def id(self) -> str:
        return "destructive-command-blocklist"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.TOOL_CALL

    @property
    def description(self) -> str:
        return "Blocks destructive shell commands like rm -rf or wget."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        # Expect payload to be a dict representing tool call args
        if not isinstance(payload, dict):
            return RuleResult(action=RuleAction.ALLOW)

        tool_name = payload.get("tool_name", "")
        if tool_name not in ["BashExecutioner", "shell", "bash", "cmd"]:
            return RuleResult(action=RuleAction.ALLOW)

        command = payload.get("args", {}).get("command", "")
        if not isinstance(command, str) or not command:
            return RuleResult(action=RuleAction.ALLOW)

        command_lower = command.lower()
        dangerous_patterns = [
            re.compile(r'\brm\s+-r'),           # Recursive remove
            re.compile(r'\bmv\s+.*\/dev\/null'),# Moving to dev null
            re.compile(r'\bwget\b'),            # Downloading external scripts
            re.compile(r'\bcurl\b.*\|.*bash'),  # Piping curl to bash
            re.compile(r'\bchmod\s+-r\s+777'),  # Recursive chmod 777
            re.compile(r'\bmkfs\b'),            # Formatting file systems
            re.compile(r'\bdd\b')               # Block copying (dd)
        ]

        for pattern in dangerous_patterns:
            if pattern.search(command_lower):
                return RuleResult(
                    action=RuleAction.BLOCK,
                    reason=f"Command matched restricted pattern: {pattern.pattern}"
                )

        return RuleResult(action=RuleAction.ALLOW)


class NetworkAllowlistRule(FirewallRule):
    """
    Intercepts URL payloads and drops requests unless the domain is on the allowlist.
    """
    def __init__(self, allowed_domains: List[str]):
        self.allowed_domains = allowed_domains

    @property
    def id(self) -> str:
        return "network-allowlist"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.TOOL_CALL

    @property
    def description(self) -> str:
        return "Restricts network calls to a specific allowlist of domains."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, dict):
            return RuleResult(action=RuleAction.ALLOW)

        tool_name = payload.get("tool_name", "")
        if tool_name not in ["fetch", "http_request", "curl", "requests"]:
            return RuleResult(action=RuleAction.ALLOW)

        url = payload.get("args", {}).get("url", "")
        if not isinstance(url, str) or not url:
            return RuleResult(action=RuleAction.ALLOW)

        # Extract domain from url (basic extraction)
        domain_match = re.search(r'https?://([^/]+)', url)
        if not domain_match:
            return RuleResult(action=RuleAction.BLOCK, reason="Invalid URL format.")

        domain = domain_match.group(1)

        # Check if domain ends with any of the allowed domains
        is_allowed = any(domain == allowed or domain.endswith('.' + allowed) for allowed in self.allowed_domains)

        if not is_allowed:
            return RuleResult(action=RuleAction.BLOCK, reason=f"Domain '{domain}' is not in the allowlist.")

        return RuleResult(action=RuleAction.ALLOW)


class FileSystemJailRule(FirewallRule):
    """
    Enforces a strict directory path for file read/write tools to prevent directory traversal.
    """
    def __init__(self, allowed_base_dir: str):
        self.allowed_base_dir = os.path.abspath(allowed_base_dir)

    @property
    def id(self) -> str:
        return "file-system-jail"

    @property
    def phase(self) -> RulePhase:
        return RulePhase.TOOL_CALL

    @property
    def description(self) -> str:
        return "Prevents directory traversal outside the sandbox."

    def evaluate(self, payload: Any, context: Optional[dict] = None) -> RuleResult:
        if not isinstance(payload, dict):
            return RuleResult(action=RuleAction.ALLOW)

        tool_name = payload.get("tool_name", "")
        if tool_name not in ["read_file", "write_file", "fs"]:
            return RuleResult(action=RuleAction.ALLOW)

        file_path = payload.get("args", {}).get("path", "")
        if not isinstance(file_path, str) or not file_path:
            return RuleResult(action=RuleAction.ALLOW)

        # Resolve path and check prefix
        # Use realpath to resolve symlinks and prevent symlink-based escapes
        resolved_path = os.path.realpath(file_path)
        allowed_base_real = os.path.realpath(self.allowed_base_dir)

        # Use commonpath to ensure the resolved path strictly falls under the allowed base directory
        # This avoids the "startswith" vulnerability where "/sandbox_escape" starts with "/sandbox"
        try:
            if os.path.commonpath([allowed_base_real, resolved_path]) != allowed_base_real:
                raise ValueError()
        except ValueError:
            return RuleResult(
                action=RuleAction.BLOCK,
                reason="Attempted path traversal outside of the allowed sandbox directory."
            )

        return RuleResult(action=RuleAction.ALLOW)
