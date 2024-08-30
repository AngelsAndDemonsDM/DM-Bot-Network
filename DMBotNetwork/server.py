import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import msgpack

from .server_db import ServerDB

logger = logging.getLogger("DMBotNetwork Server main")


class Server:
    _net_methods: Dict[str, Any] = {}
    _connects: Dict[str, StreamWriter] = {}
    _access_token: set[str] = {}
    _time_out: float = 30.0

    _host: Optional[str] = None
    _main_port: Optional[int] = None
    _file_port: Optional[int] = None
    _server_name: Optional[str] = None
    _db_path: Optional[Path] = None
    _base_owner_password: Optional[str] = None
    _allow_register: bool = True

    _is_online: bool = False
    _main_server: Optional[asyncio.AbstractServer] = None
    _file_server: Optional[asyncio.AbstractServer] = None

    # ---------------------
    # Работа с net_* методами
    # ---------------------
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        cls._net_methods = {
            method[4:]: getattr(cls, method)
            for method in dir(cls)
            if callable(getattr(cls, method)) and method.startswith("net_")
        }

    @classmethod
    async def _call_method(
        cls, methods_dict: Dict[str, Any], method_name: str, **kwargs
    ) -> Any:
        method = methods_dict.get(method_name)
        if method is None:
            logger.error(f"Net method {method_name} not found.")
            return None

        sig = inspect.signature(method)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        try:
            if inspect.iscoroutinefunction(method):
                return await method(cls, **valid_kwargs)
            else:
                return method(cls, **valid_kwargs)

        except Exception as e:
            logger.error(f"Error calling method {method_name}: {e}")
            return None

    # ---------------------
    # SetUp
    # ---------------------
    @classmethod
    def set_up_all(
        cls,
        host: str = "localhost",
        main_port: int = 5000,
        file_port: int = 5001,
        server_name: str = "dev_server",
        db_path: Optional[Path | str] = None,
        base_owner_password: Optional[str] = None,
        allow_register: bool = True,
        time_out: float = 30.0,
    ) -> None:
        cls._host = host
        cls._main_port = main_port
        cls._file_port = file_port
        cls._server_name = server_name
        cls._allow_register = allow_register
        cls._time_out = time_out

        ServerDB.set_db_path(db_path)
        ServerDB.set_owner_base_password(base_owner_password)

    @classmethod
    def set_time_out(cls, value: float) -> None:
        cls._time_out = value

    @classmethod
    def set_allow_register(cls, value: bool) -> None:
        cls._allow_register = value

    # ---------------------
    # Работа с запуском
    # ---------------------
    @classmethod
    async def start(cls) -> None:
        try:
            ServerDB.start()

            cls._main_server = await asyncio.start_server(
                cls._main_handler, cls._host, cls._main_port
            )

            cls._file_server = await asyncio.start_server(
                cls._file_handler, cls._host, cls._file_port
            )

            cls._is_online = True

            async with cls._main_server, cls._file_server:
                logger.info(
                    f"Server setup. Host: {cls._host}, file_port:{cls._file_port}, main_port:{cls._main_port}"
                )

                await asyncio.gather(
                    cls._main_server.serve_forever(), cls._file_server.serve_forever()
                )

        except asyncio.CancelledError:
            await cls.stop()

        except Exception as e:
            logger.error(f"Error starting server: {e}")
            await cls.stop()

    @classmethod
    async def stop(cls) -> None:
        ServerDB.stop()

        await asyncio.gather(
            *(
                cls._close_connection(writer=writer, login=login)
                for login, writer in cls._connects.items()
            )
        )

        if cls._main_server:
            cls._main_server.close()
            await cls._main_server.wait_closed()

        if cls._file_server:
            cls._file_server.close()
            await cls._file_server.wait_closed()

        logger.info("Server stop")

    # ---------------------
    # Handlers
    # ---------------------
    @classmethod
    async def _main_handler(cls, reader: StreamReader, writer: StreamWriter) -> None:
        try:
            login = await cls._auth(reader, writer)
            if not login:
                await cls._close_connection(writer)
                return

        except asyncio.TimeoutError:
            await cls.send_log(writer, "Timeout", "error")
            await cls._close_connection(writer)
            return

        except ValueError as err:
            await cls.send_log(writer, str(err), "error")
            await cls._close_connection(writer)
            return

        logger.info(f"{login} connected to server")
        cls._connects[login] = writer

        try:
            while cls._is_online:
                data = await cls._get_package(reader)
                if not isinstance(data, dict):
                    await cls.send_log(writer, "Invalid data type")
                    continue

                if data.get("action_type", None) == "net":
                    answer = await cls._call_method(
                        cls._net_methods, data.get("net_type", None), **data
                    )
                    await cls.send_package(writer, answer)

        except Exception as err:
            logger.error(f"Error while connect to {login}: {err}")

        finally:
            logger.info(f"{login} disconnected from server")
            cls._close_connection(writer, login)

    @classmethod
    async def _file_handler(cls, reader: StreamReader, writer: StreamWriter) -> None:
        pass

    # ---------------------
    # Auth
    # ---------------------
    @classmethod
    async def _auth(cls, reader: StreamReader, writer: StreamWriter) -> Optional[str]:
        await cls.send_req(writer, "auth")
        answer = asyncio.wait_for(cls._get_package(reader), cls._time_out)

        if not isinstance(answer, dict):
            raise ValueError("Answer must be a dict")

        auth_type = answer.get("auth_type", None)
        if not auth_type:
            raise ValueError("Answer doesn't have auth_type")

        login = answer.get("login", None)
        if not login:
            raise ValueError("Answer doesn't have login")

        password = answer.get("password", None)
        if not password:
            raise ValueError("Answer doesn't have password")

        if auth_type == "alp":
            if await ServerDB.login_user(login, password):
                return login

            await cls.send_log(writer, "Invalid login/password", "error")
            return None

        elif auth_type == "reg":
            if not cls._allow_register:
                await cls.send_log(writer, "Register is not allowed", "error")
                return None

            if await ServerDB.add_user(login, password):
                return login

            else:
                await cls.send_log(writer, "User already exists", "error")
                return None

        else:
            raise ValueError("Unknown auth_type")

    # ---------------------
    # Get data for main server
    # ---------------------
    async def _get_package(cls, reader: StreamReader) -> Any:
        data_size_bytes = await reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, "big")
        packed_data = await reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)
    
    # ---------------------
    # Send data for main server
    # ---------------------
    @classmethod
    async def send_by_login(cls, login: str, func: Callable, **kwargs) -> None:
        if login not in cls._connects:
            return

        await func(cls._connects[login], **kwargs)

    @classmethod
    async def send_log(
        cls, writer: StreamWriter, message: str, log_type: str = "info"
    ) -> None:
        payload = {"action_type": "log", "log_type": log_type, "message": message}

        await cls._send_raw(writer, msgpack.packb(payload))

    @classmethod
    async def send_req(cls, writer: StreamWriter, req_type: str, **kwargs) -> None:
        payload = {"action_type": "req", "req_type": req_type, **kwargs}

        await cls._send_raw(writer, msgpack.packb(payload))

    @classmethod
    async def broadcast(cls, data: Any) -> None:
        package = msgpack.packb(data)
        await asyncio.gather(
            *(cls._send_raw(writer, package) for writer in cls._connects.values()),
            return_exceptions=True,
        )

    @classmethod
    async def send_package(cls, writer: StreamWriter, data: Any) -> None:
        package = msgpack.packb(data)
        await cls._send_raw(writer, package)

    @classmethod
    async def _send_raw(cls, writer: StreamWriter, data: bytes) -> None:
        writer.write(len(data).to_bytes(4, byteorder="big"))
        await writer.drain()

        writer.write(data)
        await writer.drain()

    # ---------------------
    # Client worck
    # ---------------------
    @classmethod
    async def _close_connection(
        cls, writer: StreamWriter, login: Optional[str] = None
    ) -> None:
        if login and login in cls._connects:
            del cls._connects[login]

        writer.close()
        await writer.wait_closed()
