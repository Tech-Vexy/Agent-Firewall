import pytest
import json
from agent_firewall.llm_scanner import LLMScanner
from agent_firewall.models import Intent
from unittest.mock import MagicMock

def test_llm_scanner_empty_intents():
    scanner = LLMScanner(api_key="fake")
    res = scanner.scan("test input", intents=[])
    assert res.is_safe is True

def test_llm_scanner_malformed_json(mocker):
    scanner = LLMScanner(api_key="fake")

    # Mock the chat.completions.create to return a bad string instead of json
    mock_response = MagicMock()
    mock_response.choices[0].message.content = "Not a JSON object"

    mocker.patch.object(scanner.client.chat.completions, 'create', return_value=mock_response)

    intent = Intent(name="test", description="test intent")

    with pytest.raises(RuntimeError) as excinfo:
        scanner.scan("some input", intents=[intent])

    assert "LLM Scanner failed" in str(excinfo.value)

def test_llm_scanner_api_error(mocker):
    scanner = LLMScanner(api_key="fake")

    # Mock the chat.completions.create to raise an Exception
    mocker.patch.object(scanner.client.chat.completions, 'create', side_effect=Exception("Network error"))

    intent = Intent(name="test", description="test intent")

    with pytest.raises(RuntimeError) as excinfo:
        scanner.scan("some input", intents=[intent])

    assert "Network error" in str(excinfo.value)

def test_llm_scanner_success(mocker):
    scanner = LLMScanner(api_key="fake")

    # Mock a successful JSON string return
    mock_response = MagicMock()
    mock_response.choices[0].message.content = json.dumps({
        "is_safe": False,
        "intent_detected": "prompt_injection",
        "is_predictive_threat": False,
        "risk_score": 0.9,
        "reason": "Test"
    })

    mocker.patch.object(scanner.client.chat.completions, 'create', return_value=mock_response)

    intent = Intent(name="test", description="test intent")
    res = scanner.scan("some input", intents=[intent])

    assert res.is_safe is False
    assert res.intent_detected == "prompt_injection"
    assert res.risk_score == 0.9
