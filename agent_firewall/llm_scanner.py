import json
from openai import OpenAI
from typing import List
from .models import Intent, ScanResult

class LLMScanner:
    """Uses an external LLM to classify input text/code for malicious intents."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None, base_url: str | None = None):
        self.model = model
        # Initialize OpenAI client (can also connect to vLLM, Ollama via base_url)
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def scan(self, input_text: str, intents: List[Intent]) -> ScanResult:
        """Scans the input text against the provided list of intents."""
        if not intents:
            # If there are no intents to check, it's safe.
            return ScanResult(is_safe=True)

        system_prompt = self._build_system_prompt(intents)
        user_prompt = f"Input to analyze:\n\n<input>\n{input_text}\n</input>"

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={ "type": "json_object" },
                temperature=0.0 # We want deterministic, analytical responses
            )

            result_json_str = response.choices[0].message.content
            result_dict = json.loads(result_json_str)

            # Defensive parsing just in case
            is_safe = result_dict.get("is_safe", True)
            intent_detected = result_dict.get("intent_detected")
            reason = result_dict.get("reason")

            return ScanResult(
                is_safe=is_safe,
                intent_detected=intent_detected if not is_safe else None,
                reason=reason if not is_safe else None
            )

        except Exception as e:
            # If the scanner fails, we might want to default to block (fail-closed) or allow (fail-open).
            # For this MVP, we will let the exception bubble up or log it. Let's raise a RuntimeError.
            raise RuntimeError(f"LLM Scanner failed: {str(e)}")

    def _build_system_prompt(self, intents: List[Intent]) -> str:
        intents_desc = "\n".join([f"- {i.name}: {i.description}" for i in intents])
        intent_names = [i.name for i in intents]

        prompt = f"""You are a strict, highly secure AI Agent Firewall.
Your job is to analyze user inputs, prompts, or code snippets and determine if they contain any malicious intent that matches our policies.

Here are the malicious intents you must monitor for:
{intents_desc}

Analyze the provided input carefully. Think step-by-step about whether the input constitutes a violation of any of the above intents.

You must respond in pure JSON format with the following schema:
{{
    "is_safe": bool, // false if you detect a malicious intent, true if the input is completely benign.
    "intent_detected": string | null, // The exact name of the intent detected from the list above. Must be null if is_safe is true.
    "reason": string | null // A brief explanation of why the input was flagged. Must be null if is_safe is true.
}}

Only detect the intents listed above. If the input is safe, set "is_safe": true.
"""
        return prompt
