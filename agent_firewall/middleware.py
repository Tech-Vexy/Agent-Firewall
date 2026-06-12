from functools import wraps
from typing import Callable, Any
from .firewall import AgentFirewall

def protect(
    firewall: AgentFirewall,
    extract_input: Callable[..., str] = None,
    extract_session_id: Callable[..., str | None] = None
):
    """
    A generic Python decorator (middleware) to protect a function.

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
            # 1. Extract the text/code and session_id to analyze
            text_to_scan = extractor(*args, **kwargs)
            session_id = session_extractor(*args, **kwargs)

            # 2. Verify with the firewall (raises FirewallBlockedException if unsafe)
            if text_to_scan:
                firewall.verify(text_to_scan, session_id=session_id)

            # 3. Proceed with normal execution if safe
            return func(*args, **kwargs)
        return wrapper
    return decorator
