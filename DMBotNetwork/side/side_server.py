import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional, Set, get_type_hints

from ..units import ClientUnit
from ..utils import NetCode, ServerDB

logger = logging.getLogger("DMBotNetwork.Server")


class Server:
    _network_methods: Dict[str, Any] = {}

    _connections: Dict[str, ClientUnit] = {}
    _one_time_token: Set[str] = {}

    _allow_registration: bool = True
    _timeout: float = 30.0
    _server_name: str = None

    _is_online: bool = False
    _main_server: Optional[asyncio.AbstractServer] = None

    # network methods managment
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        cls._network_methods = {
            method[4:]: getattr(cls, method)
            for method in dir(cls)
            if callable(getattr(cls, method)) and method.startswith("net_")
        }

    @classmethod
    async def _call_method(
        cls,
        method_name: str,
        cl_unit: ClientUnit,
        **kwargs,
    ) -> None:
        method = cls._network_methods.get(method_name)
        if method is None:
            await cl_unit.log_error(f"Network method '{method_name}' not found.")
            return

        sig = inspect.signature(method)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        type_hints = get_type_hints(method)

        for arg_name, arg_value in valid_kwargs.items():
            expected_type = type_hints.get(arg_name, Any)
            if not isinstance(arg_value, expected_type) and expected_type is not Any:
                await cl_unit.log_error(
                    f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                )
                return

        try:
            if inspect.iscoroutinefunction(method):
                await method(cls, **valid_kwargs)

            else:
                method(cls, **valid_kwargs)

        except Exception as e:
            logger.error(f"Error calling method '{method_name}' in {cls.__name__}: {e}")

    # Status control
    @classmethod
    async def start(
        cls,
        host: str = "localhost",
        main_port: int = 5000,
        db_file_path: Path | str = None,
        base_owner_password: str = "owner_password",
        timeout: float = 30.0,
        allow_registration: bool = True,
        base_access_flags: Dict[str, bool] = {},
        server_name: str = "dev_bot",
    ) -> None:
        if cls._is_online:
            logger.warning("Server is already working")
            return

        ServerDB.set_base_access(base_access_flags)
        ServerDB.set_owner_base_password(base_owner_password)
        ServerDB.set_db_path(db_file_path)

        await ServerDB.start()

        cls._allow_registration = allow_registration
        cls._timeout = timeout

        cls._main_server = await asyncio.start_server(
            cls._main_client_handler, host, main_port
        )

        cls._is_online = True
        try:
            async with cls._main_server:
                logger.info(f"Server setup. Host: {host}, main_port:{main_port}")

                await cls._main_server.serve_forever()

        except asyncio.CancelledError:
            await cls.stop()

        except Exception as err:
            logger.error(f"Error starting server: {err}")
            await cls.stop()

    @classmethod
    async def stop(cls) -> None:
        if not cls._is_online:
            logger.warning("Server is not working")
            return

        await asyncio.gather(
            *(cl_unit.close() for cl_unit in cls._connections.values())
        )

        if cls._main_server:
            cls._main_server.close()
            await cls._main_server.wait_closed()

        cls._connections.clear()
        await ServerDB.stop()

        logger.info("Server stop")

    # SetGet allow_registration & timeout
    @classmethod
    def get_allow_registration(cls) -> bool:
        return cls._allow_registration

    @classmethod
    def set_allow_registration(cls, value: bool) -> None:
        cls._allow_registration = value

    @classmethod
    def get_timeout(cls) -> float:
        return cls._timeout

    @classmethod
    def set_timeout(cls, value: float) -> None:
        cls._timeout = value

    # Server client handlers
    @classmethod
    async def _main_client_handler(
        cls, reader: StreamReader, writer: StreamWriter
    ) -> None:
        cl_unit = ClientUnit("init...", writer, reader)
        try:
            await cls._auth(cl_unit)

        except TimeoutError:
            await cl_unit.log_error("Timeout while auth")
            await cl_unit.close()
            return

        except ValueError as err:
            await cl_unit.log_error(str(err))
            await cl_unit.close()
            return

        except Exception as err:
            await cl_unit.log_error(f"Unexpected error: {err}")
            await cl_unit.close()
            return

        cls._connections[cl_unit.login] = cl_unit

        try:
            while cls._is_online:
                receive_packet = await cl_unit._receive_packet()
                if not isinstance(receive_packet, dict):
                    await cl_unit.log_error("Get data type expected dict")
                    continue

                code = receive_packet.get("code", None)
                if not code:
                    await cl_unit.log_error("Get data must has 'code' key")
                    continue

                if not isinstance(code, int):
                    await cl_unit.log_error("'code' type expected int")
                    continue

                if code == NetCode.REQ_NET:
                    await cls._call_method(
                        receive_packet.get("type", None), cl_unit, **receive_packet
                    )

                else:
                    await cl_unit.log_error("Unknown 'code' type")

        except Exception as err:
            await cl_unit.log_error(str(err))

        finally:
            await cl_unit.close()
            del cls._connections[cl_unit.login]

    # Auth
    @classmethod
    async def _auth(cls, cl_unit: ClientUnit) -> None:
        await cl_unit.send_packet(NetCode.REQ_AUTH, server_name=cls._server_name)
        receive_packet = await asyncio.wait_for(cl_unit._receive_packet(), cls._timeout)

        if not isinstance(receive_packet, dict):
            raise ValueError("Get data type expected dict")

        code = receive_packet.get("code", None)
        if not code:
            raise ValueError("Get data must has 'code' key")

        if not isinstance(code, int):
            raise ValueError("'code' type expected int")

        if "login" not in receive_packet or "password" not in receive_packet:
            raise ValueError("Get data must has 'login' and 'password' keys")

        if code == NetCode.ANSWER_AUTH_ALP:
            await ServerDB.login_user(
                receive_packet["login"], receive_packet["password"]
            )
            cl_unit.login = receive_packet["login"]
            return

        if code == NetCode.ANSWER_AUTH_REG:
            if not cls._allow_registration:
                raise ValueError("Registration is not allowed")

            await ServerDB.add_user(receive_packet["login"], receive_packet["password"])
            cl_unit.login = receive_packet["login"]
            return

        raise ValueError("Unknown 'code' type")
