import inspect
import logging
from collections.abc import Callable
from typing import Any, Dict, get_type_hints

logger = logging.getLogger("DMBN:Client")


class Client:
    _network_funcs: Dict[str, Callable] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        cls._network_funcs = {
            func[4:]: getattr(cls, func)
            for func in dir(cls)
            if callable(getattr(cls, func)) and func.startswith("net_")
        }

    @classmethod
    async def _call_func(
        cls,
        func_name: str,
        **kwargs,
    ) -> None:
        func = cls._network_funcs.get(func_name)
        if func is None:
            logger.debug(f"Network func '{func_name}' not found.")
            return

        sig = inspect.signature(func)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        type_hints = get_type_hints(func)

        for arg_name, arg_value in valid_kwargs.items():
            expected_type = type_hints.get(arg_name, Any)
            if not isinstance(arg_value, expected_type) and expected_type is not Any:
                logger.error(
                    f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                )
                return

        try:
            if inspect.iscoroutinefunction(func):
                await func(cls, **valid_kwargs)

            else:
                func(cls, **valid_kwargs)

        except Exception as e:
            logger.error(f"Error calling method '{func_name}' in {cls.__name__}: {e}")
