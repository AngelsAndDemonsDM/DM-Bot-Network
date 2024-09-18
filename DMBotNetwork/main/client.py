import asyncio
import base64
import inspect
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import (Any, Dict, List, Optional, Type, Union, get_args,
                    get_origin, get_type_hints)

import aiofiles

from .utils import ResponseCode

logger = logging.getLogger("DMBN:Client")


class Client:
    _network_funcs: Dict[str, Callable] = {}
    _server_handler_task: Optional[asyncio.Task] = None
    _disconnect_lock = asyncio.Lock()

    _data_cache: Dict[str, Any] = {}
    _waiting_tasks: Dict[str, asyncio.Event] = {}

    _server_name: str = "dev_server"
    _reader: Optional[asyncio.StreamReader] = None
    _writer: Optional[asyncio.StreamWriter] = None

    _is_auth: bool = False
    _is_connected: bool = False

    _login: str = "owner"
    _password: str = "owner_password"
    _use_registration: bool = False
    _content_path: Path = Path("")

    @classmethod
    def register_methods_from_class(cls, external_classes: Type | List[Type]) -> None:
        """Регистрация методов с префиксом 'net_' из внешнего класса."""
        if not isinstance(external_classes, list):
            external_classes = [external_classes]

        for external_class in external_classes:
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
            if get_origin(expected_type) is Union:
                if not isinstance(arg_value, get_args(expected_type)):
                    logger.error(
                        f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                    )
                    return

            else:
                if not isinstance(arg_value, expected_type):
                    logger.error(
                        f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                    )
                return

        try:
            if inspect.iscoroutinefunction(func):
                await func(**valid_kwargs)

            else:
                func(**valid_kwargs)

        except Exception as e:
            logger.error(f"Error calling method '{func_name}' in {cls.__name__}: {e}")

    @classmethod
    async def send_package(cls, code: ResponseCode, **kwargs) -> None:
        payload = {"code": code.value, **kwargs}
        en_data = cls._encode_data(payload)
        await cls._send_raw_data(en_data)

    @classmethod
    async def req_net_func(cls, func_name: str, **kwargs) -> None:
        await cls.send_package(ResponseCode.NET_REQ, net_func_name=func_name, **kwargs)

    @classmethod
    async def req_get_data(cls, func_name: str, get_key: str, **kwargs) -> Any:
        if get_key in cls._data_cache:
            return cls._data_cache.pop(get_key)

        if get_key not in cls._waiting_tasks:
            cls._waiting_tasks[get_key] = asyncio.Event()
            await cls.send_package(
                ResponseCode.GET_REQ,
                net_func_name=func_name,
                net_get_key=get_key,
                **kwargs,
            )

        await cls._waiting_tasks[get_key].wait()
        cls._waiting_tasks.pop(get_key, None)
        return cls._data_cache.pop(get_key)

    @classmethod
    async def _handle_data_from_server(cls, get_key: str, data: Any) -> None:
        """Обработка полученных данных от сервера."""
        cls._data_cache[get_key] = data
        if get_key in cls._waiting_tasks:
            cls._waiting_tasks[get_key].set()

    @classmethod
    def is_connected(cls) -> bool:
        return cls._is_auth and cls._is_connected

    @classmethod
    def get_server_name(cls) -> str:
        return cls._server_name

    @classmethod
    def get_login(cls) -> str:
        return cls._login

    @classmethod
    def setup(
        cls, login: str, password: str, use_registration: bool, content_path: str | Path
    ) -> None:
        """Настройка клиента перед подключением.

        Args:
            login (str): Логин пользователя.
            password (str): Пароль пользователя.
            use_registration (bool): Флаг использования регистрации вместо авторизации.
            content_path (str | Path): Путь для сохранения файлов.

        Raises:
            ValueError: Если один из параметров некорректен.
        """
        if not all([login, password]):
            raise ValueError("Login, password cannot be empty")

        cls._login = login
        cls._password = password
        cls._use_registration = use_registration

        content_path = Path(content_path)
        if content_path.exists() and not content_path.is_dir():
            raise ValueError(f"{content_path} not a dir")

        content_path.mkdir(parents=True, exist_ok=True)
        cls._content_path = content_path

    @classmethod
    async def connect(cls, host, port) -> None:
        try:
            cls._reader, cls._writer = await asyncio.open_connection(host, port)
            cls._is_connected = True

            logger.info(f"Connected to {host}:{port}")

            cls._server_handler_task = asyncio.create_task(cls._server_handler())

        except Exception as err:
            logger.error(f"Error while connect to sever: {err}")
            await cls.disconnect()

    @classmethod
    async def disconnect(cls) -> None:
        async with cls._disconnect_lock:
            cls._is_connected = False
            cls._is_auth = False

            if cls._writer:
                try:
                    cls._writer.close()
                    await cls._writer.wait_closed()

                except ConnectionAbortedError:
                    pass

                except Exception as err:
                    logger.error(f"Error during disconnect: {err}")

            if cls._server_handler_task:
                cls._server_handler_task.cancel()
                cls._server_handler_task = None

            cls._writer = None
            cls._reader = None

            download_files = cls._content_path.glob("**/*.download")
            for file in download_files:
                file.unlink()

            logger.info("Disconnected from server")

    @classmethod
    async def _server_handler(cls) -> None:
        try:
            while cls._is_connected:
                receive_package = await cls._receive_package()

                code = receive_package.pop("code", None)
                if not code:
                    logger.error(f"Receive data must has 'code' key: {receive_package}")
                    continue

                if code == ResponseCode.NET_REQ:
                    await cls._call_func(
                        receive_package.pop("net_func_name", None),
                        **receive_package,
                    )

                elif code == ResponseCode.GET_REQ:
                    get_key = receive_package.pop("get_key", None)
                    data = receive_package.pop("data", None)
                    if get_key:
                        await cls._handle_data_from_server(get_key, data)

                elif ResponseCode.is_log(code):
                    cls._log_handler(code, receive_package)

                elif ResponseCode.is_auth(code):
                    await cls._auth_handler(code, receive_package)

                elif ResponseCode.is_file(code):
                    await cls._file_handler(code, receive_package)

                else:
                    logger.error(f"Unknown 'code' for net type: {receive_package}")

        except (
            asyncio.CancelledError,
            ConnectionAbortedError,
            asyncio.exceptions.IncompleteReadError,
            ConnectionResetError,
        ):
            pass

        except Exception as err:
            logger.error(str(err))

        finally:
            await cls.disconnect()

    @classmethod
    def _log_handler(cls, code: int, receive_package: dict) -> None:
        message = receive_package.get("message", None)
        message = f"Server log: {message}"

        if code == ResponseCode.LOG_DEB:
            logger.debug(message)

        elif code == ResponseCode.LOG_INF:
            logger.info(message)

        elif code == ResponseCode.LOG_WAR:
            logger.warning(message)

        elif code == ResponseCode.LOG_ERR:
            logger.warning(message)

        else:
            logger.warning(f"Unknown 'code': {receive_package}")

    @classmethod
    async def _auth_handler(cls, code: int, receive_package: dict) -> None:
        if code == ResponseCode.AUTH_REQ:
            await cls.send_package(
                ResponseCode.AUTH_ANS_REGIS
                if cls._use_registration
                else ResponseCode.AUTH_ANS_LOGIN,
                login=cls._login,
                password=cls._password,
            )

        elif code == ResponseCode.AUTH_ANS_SERVE:
            server_name = receive_package.get("server_name", None)
            if not server_name:
                return

            cls._is_auth = True
            cls._server_name = server_name

    @classmethod
    async def _file_handler(cls, code: int, receive_package: dict) -> None:
        if code == ResponseCode.FIL_REQ:
            name = receive_package.get("name", None)
            chunk_base64 = receive_package.get("chunk", None)

            if not all([name, chunk_base64]):
                return

            file_path: Path = (
                cls._content_path / cls._server_name / (name + ".download")
            )
            file_path.parent.mkdir(parents=True, exist_ok=True)

            chunk = base64.b64decode(chunk_base64.encode("utf-8"))

            async with aiofiles.open(file_path, "ab") as file:
                await file.write(chunk)

        elif code == ResponseCode.FIL_END:
            name = receive_package.get("name", None)
            if not name:
                return

            file_path: Path = (
                cls._content_path / cls._server_name / (name + ".download")
            )
            final_file_path: Path = cls._content_path / cls._server_name / name

            if file_path.exists():
                file_path.rename(final_file_path)

    @classmethod
    async def _receive_package(cls) -> dict:
        raw_data = await cls._receive_raw_data()
        return cls._decode_data(raw_data)

    @classmethod
    def _encode_data(cls, data: dict) -> bytes:
        json_data = json.dumps(data, ensure_ascii=False)
        return json_data.encode("utf-8")

    @classmethod
    def _decode_data(cls, encoded_data: bytes) -> dict:
        json_data = encoded_data.decode("utf-8")
        return json.loads(json_data)

    @classmethod
    async def _send_raw_data(cls, data: bytes) -> None:
        if not cls._writer:
            raise RuntimeError("Is not connected")

        cls._writer.write(len(data).to_bytes(4, "big"))
        await cls._writer.drain()

        cls._writer.write(data)
        await cls._writer.drain()

    @classmethod
    async def _receive_raw_data(cls) -> bytes:
        if not cls._reader:
            raise RuntimeError("Is not connected")

        data_length_bytes = await cls._reader.readexactly(4)
        data_length = int.from_bytes(data_length_bytes, "big")

        return await cls._reader.readexactly(data_length)
