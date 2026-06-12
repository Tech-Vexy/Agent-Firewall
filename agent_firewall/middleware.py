from functools import wraps
from typing import Callable, Any
from .firewall import AgentFirewall

def protect(firewall: AgentFirewall, extract_input: Callable[..., str] = None):
    """
    A generic Python decorator (middleware) to protect a function.

    Args:
        firewall: An instance of AgentFirewall.
        extract_input: A callable that takes the decorated function's args and kwargs,
                       and returns a single string to be scanned by the firewall.
                       If None, the decorator will attempt to cast the first positional
                       argument or the 'prompt' / 'input' kwarg to a string.
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

    extractor = extract_input if extract_input else default_extractor

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 1. Extract the text/code to analyze
            text_to_scan = extractor(*args, **kwargs)

            # 2. Verify with the firewall (raises FirewallBlockedException if unsafe)
            if text_to_scan:
                firewall.verify(text_to_scan)

            # 3. Proceed with normal execution if safe
            return func(*args, **kwargs)
        return wrapper
    return decorator
