import asyncio
import inspect
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict, Optional, get_type_hints

from .utils import ClUnit, ResponseCode, ServerDB

logger = logging.getLogger("DMBN:Server")


class Server:
    _network_funcs: Dict[str, Callable] = {}
    _cl_units: Dict[str, ClUnit] = {}
    _server: Optional[asyncio.AbstractServer] = None

    _is_online: bool = False

    _server_name: str = "Dev_Server"
    _allow_registration: bool = True
    _timeout: float = 30.0

    @classmethod
    def register_methods_from_class(cls, external_class):
        """Регистрация методов с префиксом 'net_' из внешнего класса."""
        for name, func in inspect.getmembers(
            external_class, predicate=inspect.isfunction
        ):
            if name.startswith("net_"):
                method_name = name[4:]
                cls._network_funcs[method_name] = func
                logger.debug(
                    f"Registered method '{name}' from {external_class.__name__} as '{method_name}'"
                )

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

    @classmethod
    async def setup_server(
        cls,
        server_name: str,
        host: str,
        port: int,
        db_path: str | Path,
        init_owner_password: str,
        base_access: Dict[str, bool],
        allow_registration: bool,
        timeout: float,
    ) -> None:
        cls._server_name = server_name
        cls._allow_registration = allow_registration
        cls._timeout = timeout

        ServerDB.set_db_path(db_path)
        ServerDB.set_owner_base_password(init_owner_password)
        ServerDB.set_base_access(base_access)

        cls._server = await asyncio.start_server(cls._cl_handler, host, port)
        logger.info(f"Server setup. Host: {host}, port:{port}.")

    @classmethod
    async def start(cls) -> None:
        if not cls._server:
            raise RuntimeError("Server is not initialized.")

        if cls._is_online:
            raise RuntimeError("Server already start.")

        await ServerDB.start()

        try:
            async with cls._server:
                cls._is_online = True
                logger.info("Server start.")
                await cls._server.serve_forever()

        except asyncio.CancelledError:
            pass

        except Exception as err:
            logger.error(f"Error starting server: {err}")

        finally:
            await cls.stop()

    @classmethod
    async def stop(cls) -> None:
        if not cls._is_online:
            raise RuntimeError("Server is not working.")

        cls._is_online = False

        asyncio.gather(*(cl_unit.disconnect() for cl_unit in cls._cl_units.values()))
        cls._cl_units.clear()

        if cls._server:
            cls._server.close()
            await cls._server.wait_closed()

        await ServerDB.stop()
        logger.info("Server stop.")

    @classmethod
    async def broadcast(cls, func_name: str, *args, **kwargs) -> None:
        tasks = []
        for cl_unit in cls._cl_units.values():
            func = getattr(cl_unit, func_name, None)
            if callable(func):
                tasks.append(func(*args, **kwargs))

            else:
                logger.error(f"{func_name} is not a callable method of {cl_unit}")

        if tasks:
            await asyncio.gather(*tasks)

    @classmethod
    async def _cl_handler(
        cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cl_unit = ClUnit("init", reader, writer)

        try:
            await cls._auth(cl_unit)

        except TimeoutError:
            await cl_unit.send_log_error("Timeout for auth.")
            await cl_unit.disconnect()
            return

        except ValueError as err:
            await cl_unit.send_log_error(str(err))
            await cl_unit.disconnect()
            return

        except Exception as err:
            await cl_unit.send_log_error(f"An unexpected error occurred: {err}")
            await cl_unit.disconnect()
            return

        cls._cl_units[cl_unit.login] = cl_unit
        logger.info(f"{cl_unit.login} is connected.")

        try:
            while cls._is_online:
                receive_package = await cl_unit.receive_package()
                if not isinstance(receive_package, dict):
                    await cl_unit.send_log_error("Receive data type expected dict.")
                    continue

                code = receive_package.pop("code", None)
                if not code:
                    await cl_unit.send_log_error("Receive data must has 'code' key.")
                    continue

                if ResponseCode.is_net(code):
                    func_name = receive_package.pop("net_func_name", None)
                    await cls._call_func(
                        func_name,
                        cl_unit=cl_unit,
                        **receive_package,
                    )

                else:
                    await cl_unit.send_log_error("Unknown 'code' for net type.")

        except Exception as err:
            await cl_unit.send_log_error(f"An unexpected error occurred: {err}")

        finally:
            cls._cl_units.pop(cl_unit.login, None)
            await cl_unit.disconnect()
            logger.info(f"{cl_unit.login} is disconected.")

    @classmethod
    async def _auth(cls, cl_unit: ClUnit) -> None:
        await cl_unit.send_package(ResponseCode.AUTH_REQ)
        receive_package = await asyncio.wait_for(
            cl_unit.receive_package(), cls._timeout
        )

        if not isinstance(receive_package, dict):
            raise ValueError("Receive data type expected dict.")

        code = receive_package.get("code", None)
        if not code:
            raise ValueError("Receive data must has 'code' key.")

        code = ResponseCode(code)

        if not ResponseCode.is_client_auth(code):
            raise ValueError("Unknown 'code' for auth type.")

        login = receive_package.get("login", None)
        password = receive_package.get("password", None)
        if not all([login, password]):
            raise ValueError("Receive data must has 'login' and 'password' keys.")

        if code == ResponseCode.AUTH_ANS_REGIS:
            if not cls._allow_registration:
                raise ValueError("Registration is not allowed.")

            await ServerDB.add_user(login, password)
            cl_unit.login = login

        else:
            await ServerDB.login_user(login, password)
            cl_unit.login = login

        await cl_unit.send_package(
            ResponseCode.AUTH_ANS_SERVE, server_name=cls._server_name
        )
