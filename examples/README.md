# Agent Firewall Examples

This directory contains executable examples demonstrating how to use the Agent Firewall SDK in various scenarios.

1. **`local_agent.py`**: Demonstrates how to use the `@protect_ingress`, `@protect_tool`, and `@protect_egress` middleware decorators to secure a standard Python agent.
2. **`custom_rule.py`**: Shows how to extend the `FirewallRule` class to build custom business logic (e.g., blocking mentions of competitors) and inject it into the firewall.
3. **`fwaas/`**: Contains a deployable FastAPI application demonstrating "Firewall as a Service", allowing non-Python agents to use the firewall over an HTTP API.

## Running the Examples

Make sure you have the dependencies installed:
```bash
pip install -r requirements.txt
```

To fully experience the predictive scanning capabilities, set your OpenAI API key before running the examples:
```bash
export OPENAI_API_KEY="sk-your-key"
```

Then, run any example:
```bash
python examples/local_agent.py
```
