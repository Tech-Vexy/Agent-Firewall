from functools import wraps
from typing import Callable, Any
from .firewall import AgentFirewall

def protect_ingress(
    firewall: AgentFirewall,
    extract_input: Callable[..., str] = None,
    extract_session_id: Callable[..., str | None] = None
):
    """
    A generic Python decorator (middleware) to protect an ingress function (e.g., handling user prompts).
    This will run both the modular INGRESS rules and the LLM scanner.

    Args:
        firewall: An instance of AgentFirewall.
        extract_input: A callable that takes the decorated function's args and kwargs,
                       and returns a single string to be scanned by the firewall.
                       If None, the decorator will attempt to cast the first positional
                       argument or the 'prompt' / 'input' kwarg to a string.
        extract_session_id: A callable that returns the session ID string to maintain
                            predictive memory across calls.
    """
    def default_extractor(*args, **kwargs) -> str:
        # Try to find something that looks like an input prompt or code
        if 'prompt' in kwargs:
            return str(kwargs['prompt'])
        if 'input' in kwargs:
            return str(kwargs['input'])
        if 'code' in kwargs:
            return str(kwargs['code'])
        if args:
            return str(args[0])
        return ""

    def default_session_extractor(*args, **kwargs) -> str | None:
        if 'session_id' in kwargs:
            return str(kwargs['session_id'])
        return None

    extractor = extract_input if extract_input else default_extractor
    session_extractor = extract_session_id if extract_session_id else default_session_extractor

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            text_to_scan = extractor(*args, **kwargs)
            session_id = session_extractor(*args, **kwargs)

            # Verify with the firewall (raises FirewallBlockedException if unsafe)
            # Note: `verify` will also run the modular ingress rules under the hood
            if text_to_scan:
                firewall.verify(text_to_scan, session_id=session_id)

            return func(*args, **kwargs)
        return wrapper
    return decorator


import inspect

def protect_tool(
    firewall: AgentFirewall,
    tool_name: str,
    extract_args: Callable[..., dict] = None
):
    """
    Decorator to protect a tool execution function. Runs TOOL_CALL rules.
    """

    def decorator(func: Callable) -> Callable:

        def default_args_extractor(*args, **kwargs) -> dict:
            # Bind arguments to the function signature to capture positional and keyword args
            # accurately into a single dictionary
            try:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                return dict(bound_args.arguments)
            except Exception:
                # Fallback
                if kwargs:
                    return kwargs
                if args and isinstance(args[0], dict):
                    return args[0]
                return {}

        extractor = extract_args if extract_args else default_args_extractor

        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tool_args = extractor(*args, **kwargs)

            # Evaluate tool call rules (raises exception if blocked)
            firewall.evaluate_tool_call(tool_name, tool_args)

            return func(*args, **kwargs)
        return wrapper
    return decorator


def protect_egress(
    firewall: AgentFirewall,
    extract_output: Callable[[Any], Any] = None
):
    """
    Decorator to protect agent output. Runs EGRESS rules and redacts output if necessary.
    """
    def default_extractor(result: Any) -> Any:
        return result

    extractor = extract_output if extract_output else default_extractor

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 1. Run the actual agent function
            result = func(*args, **kwargs)

            # 2. Extract the string/payload to scan
            payload_to_scan = extractor(result)

            # 3. Evaluate EGRESS rules
            if payload_to_scan is not None:
                modified_payload = firewall.evaluate_egress(payload_to_scan)

                # If a custom extractor was used, we can't easily inject the modified string back
                # into a complex object dynamically. But for simple string outputs, we can return it.
                if isinstance(result, str):
                    return modified_payload

            return result
        return wrapper
    return decorator
