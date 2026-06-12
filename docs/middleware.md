# Middleware Integration

The easiest way to integrate the Agent Firewall into a Python-based agent framework is by using our provided middleware decorators.

These decorators automatically extract payloads, pass them to the firewall, and handle blocking/redaction without cluttering your core agent logic.

## 1. Protecting Ingress (User Prompts)

Use `@protect_ingress` to wrap the function that receives user input. It will run all `INGRESS` rules and the LLM predictive scanner.

```python
from agent_firewall import protect_ingress

# Assuming `firewall` is already initialized

@protect_ingress(firewall=firewall)
def generate_response(prompt: str):
    # This function will only execute if the prompt is deemed safe.
    # Otherwise, a FirewallBlockedException is raised.
    return llm.predict(prompt)
```

If your function signature is complex, use a custom extractor to tell the middleware where to find the string to scan:

```python
def extract_message(payload: dict) -> str:
    return payload.get("message", "")

@protect_ingress(firewall=firewall, extract_input=extract_message)
def handle_socket_event(payload: dict):
    pass
```

## 2. Protecting Tool Calls (Runtime)

Use `@protect_tool` to secure the execution of tools. This runs all `TOOL_CALL` rules. The decorator automatically inspects the function signature to capture keyword and positional arguments into a dictionary payload.

```python
from agent_firewall import protect_tool

@protect_tool(firewall=firewall, tool_name="bash")
def run_shell_command(command: str, timeout: int = 30):
    import subprocess
    return subprocess.check_output(command, shell=True)

# Calling run_shell_command("rm -rf /") will be blocked by DestructiveCommandRule
```

## 3. Protecting Egress (Data Exfiltration)

Use `@protect_egress` to wrap the final output of your agent. This runs `EGRESS` rules, which can `BLOCK` or `REDACT` the data.

If a rule returns `REDACT`, the decorator will **modify the return value** of your function before it reaches the caller.

```python
from agent_firewall import protect_egress

@protect_egress(firewall=firewall)
def query_database(user_id: str):
    # Imagine this returns: "User profile: SSN 123-45-6789"
    return db.get_profile(user_id)

# If PIIRedactorRule is active, the caller receives:
# "User profile: SSN [REDACTED_SSN]"
profile = query_database("user_1")
```
