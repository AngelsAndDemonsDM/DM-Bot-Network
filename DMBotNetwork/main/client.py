import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict, Optional, get_type_hints

import aiofiles

from .utils import ResponseCode

logger = logging.getLogger("DMBN:Client")


class Client:
    _network_funcs: Dict[str, Callable] = {}
    _server_handler_task: Optional[asyncio.Task]

    _server_name: str = "dev_server"
    _reader: Optional[asyncio.StreamReader]
    _writer: Optional[asyncio.StreamWriter]

    _is_auth: bool = False
    _is_connected: bool = False

    _login: str = "owner"
    _password: str = "owner_password"
    _use_registration: bool = False
    _content_path: Path = Path("")

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

    @classmethod
    async def send_package(cls, code: ResponseCode, **kwargs) -> None:
        payload = {"code": code.value, **kwargs}
        en_data = cls._encode_data(payload)
        await cls._send_raw_data(en_data)

    @classmethod
    async def req_net_func(cls, func_name: str, **kwargs) -> None:
        await cls.send_package(ResponseCode.NET_REQ, net_func_name=func_name, **kwargs)

    @classmethod
    def is_connected(cls) -> bool:
        return cls._is_auth and cls._is_connected

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
        if not content_path.is_dir():
            raise ValueError(f"{content_path} not a dir")

        content_path.mkdir(parents=True, exist_ok=True)
        cls._content_path = content_path

    @classmethod
    async def connect(cls, host, port) -> None:
        cls._reader, cls._writer = await asyncio.open_connection(host, port)
        cls._is_connected = True

        logger.info(f"Connected to {host}:{port}")

        cls._server_handler_task = asyncio.create_task(cls._server_handler())

    @classmethod
    async def disconnect(cls) -> None:
        cls._is_connected = False
        cls._is_auth = False

        if cls._writer:
            cls._writer.close()
            await cls._writer.wait_closed()

        if cls._server_handler_task:
            cls._server_handler_task.cancel()
            cls._server_handler_task = None

        download_files = cls._content_path.glob("**/*.download")
        for file in download_files:
            file.unlink()

    @classmethod
    async def _server_handler(cls) -> None:
        try:
            while cls._is_connected:
                receive_package = await cls._receive_package()

                code = receive_package.pop("code", None)
                if not code:
                    logger.error(f"Receive data must has 'code' key: {receive_package}")
                    continue

                if ResponseCode.is_net(code):
                    await cls._call_func(
                        receive_package.pop("net_func_name", None),
                        **receive_package,
                    )

                elif ResponseCode.is_log(code):
                    cls._log_handler(code, receive_package)

                elif ResponseCode.is_auth(code):
                    await cls._auth_handler(code, receive_package)

                elif ResponseCode.is_file(code):
                    await cls._file_handler(code, receive_package)

                else:
                    logger.error(f"Unknown 'code' for net type: {receive_package}")

        except asyncio.CancelledError:
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
            chunk = receive_package.get("chunk", None)

            if not all([name, chunk]):
                return

            file_path: Path = (
                cls._content_path / cls._server_name / (name + ".download")
            )
            file_path.parent.mkdir(parents=True, exist_ok=True)

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

        message_length = len(data)
        cls._writer.write(message_length.to_bytes(4, "big") + data)
        await cls._writer.drain()

    @classmethod
    async def _receive_raw_data(cls) -> bytes:
        if not cls._reader:
            raise RuntimeError("Is not connected")

        data_length_bytes = await cls._reader.readexactly(4)
        data_length = int.from_bytes(data_length_bytes, "big")

        return await cls._reader.readexactly(data_length)
