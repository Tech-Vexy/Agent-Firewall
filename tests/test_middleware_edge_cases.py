import pytest
from agent_firewall import AgentFirewall, protect_tool, protect_egress
from agent_firewall.llm_scanner import LLMScanner
from agent_firewall.models import ScanResult
from unittest.mock import MagicMock

@pytest.fixture
def mock_scanner(mocker):
    scanner = LLMScanner(api_key="fake")
    mocker.patch.object(scanner, 'scan', return_value=ScanResult(is_safe=True))
    return scanner

def test_protect_tool_fallback_extractor(mock_scanner):
    """Test the fallback mechanism of default_args_extractor when inspect.signature fails."""
    firewall = AgentFirewall(scanner=mock_scanner)

    # We mock the evaluate_tool_call so it doesn't raise, we just want to see the args extracted
    firewall.evaluate_tool_call = MagicMock()

    @protect_tool(firewall=firewall, tool_name="dummy")
    def tool_kwargs(**kwargs):
        return "ok"

    # With kwargs
    # The signature inspection resolves **kwargs to a param named 'kwargs' containing a dict: {"kwargs": {"cmd": "test"}}
    tool_kwargs(cmd="test")
    firewall.evaluate_tool_call.assert_called_with("dummy", {"kwargs": {"cmd": "test"}})

    @protect_tool(firewall=firewall, tool_name="dummy")
    def tool_dict_arg(*args):
        return "ok"

    # With dict arg
    tool_dict_arg({"path": "/foo"})
    firewall.evaluate_tool_call.assert_called_with("dummy", {"args": ({"path": "/foo"},)})

    # With empty
    tool_dict_arg()
    firewall.evaluate_tool_call.assert_called_with("dummy", {"args": ()})

def test_protect_egress_custom_extractor_returns_none(mock_scanner):
    """Test that protect_egress skips evaluation if extractor returns None."""
    firewall = AgentFirewall(scanner=mock_scanner)
    firewall.evaluate_egress = MagicMock()

    def extractor_none(result):
        return None

    @protect_egress(firewall=firewall, extract_output=extractor_none)
    def my_agent():
        return "complex_object"

    res = my_agent()
    assert res == "complex_object"
    firewall.evaluate_egress.assert_not_called()

def test_protect_egress_non_string_result(mock_scanner):
    """Test that protect_egress does not overwrite non-string return values."""
    firewall = AgentFirewall(scanner=mock_scanner)
    # mock evaluate_egress to simulate a REDACT modification
    firewall.evaluate_egress = MagicMock(return_value="REDACTED")

    @protect_egress(firewall=firewall)
    def my_agent_dict():
        return {"data": "secret"}

    res = my_agent_dict()
    # evaluate was called with the dict (which the rule should handle via allow)
    firewall.evaluate_egress.assert_called_once_with({"data": "secret"})
    # but the result should NOT be replaced by the string "REDACTED"
    assert res == {"data": "secret"}
