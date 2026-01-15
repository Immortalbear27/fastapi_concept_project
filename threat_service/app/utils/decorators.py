from __future__ import annotations

import time
import functools
from typing import Any, Awaitable, Callable, TypeVar, ParamSpec

P = ParamSpec("P")
R = TypeVar("R")

def timed(name: str | None = None):
    """
    A decorator factory that measures execution time of an ASYNC function

    Args:
        name (str | None, optional): Optional label to identify the timed block. Defaults to None.
    """
    
    def decorator(func: Callable[P, Awaitable[R]]):
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs):
            st = time.time()
            result = func(*args, **kwargs)
            end = time.time()
            totalTime = end - st
            print("Total time for execution:", totalTime)
            return result
        return wrapper
    return decorator