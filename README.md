# Agent Firewall SDK

Agent Firewall is a powerful, extensible Python SDK designed to secure your AI Agents. It intercepts, analyzes, and blocks malicious intents, dangerous tool executions, and data exfiltration attempts.

Whether you are building an agent from scratch, using frameworks like LangChain or AutoGen, or building agents in a non-Python language, Agent Firewall has you covered.

## Core Features

- **Modular Rules Engine:** Evaluate threats across three distinct phases: Ingress (Prompt Injection), Runtime/Tool Call (Destructive Commands), and Egress (Data Exfiltration).
- **Predictive Threat Detection:** Maintains session memory to catch multi-step attacks and zero-day anomalies using an external LLM scanner.
- **Middleware Integrations:** Easy-to-use Python decorators (`@protect_ingress`, `@protect_tool`, `@protect_egress`) to secure your functions seamlessly.
- **Firewall as a Service (FWaaS):** Run the firewall as a standalone REST API to protect agents written in TypeScript, Go, or any other language.

## Documentation

Dive into our dedicated documentation to learn how to secure your agents:

1. [**Getting Started**](docs/getting_started.md): Installation and basic usage.
2. [**Rules Architecture**](docs/rules.md): Understand the phases, use built-in rules, and write your own custom rules.
3. [**Middleware Integration**](docs/middleware.md): How to use decorators to secure your Python agent framework.
4. [**Predictive Scanning & Memory**](docs/predictive_scanning.md): Catching multi-step attacks using session history.
5. [**Firewall as a Service (FWaaS)**](docs/fwaas.md): Deploying the firewall as an API for language-agnostic protection.

## Installation

```bash
pip install agent-firewall
```

*(Note: Ensure you have `OPENAI_API_KEY` set in your environment if using the predictive LLM scanner).*
