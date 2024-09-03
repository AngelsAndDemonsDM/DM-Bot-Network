import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional, get_type_hints

import msgpack

from ..utils import NCAnyType, NCLogType, NetCode

logger = logging.getLogger("DMBotNetwork Client")


class Client:
    _network_methods: Dict[str, Any] = {}
    _ear_task: Optional[asyncio.Task] = None  # lol

    _viva_alp: bool = True
    _login: Optional[str] = None
    _password: Optional[str] = None
    _content_path: Optional[Path] = None
    _temp_fold: Optional[Path] = None
    _server_name: Optional[str] = None

    _is_connected: bool = False
    _is_auth: bool = False
    _reader: Optional[StreamReader] = None
    _writer: Optional[StreamWriter] = None

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
        **kwargs,
    ) -> None:
        method = cls._network_methods.get(method_name)
        if method is None:
            logger.error(f"Network method '{method_name}' not found.")
            return

        sig = inspect.signature(method)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        type_hints = get_type_hints(method)

        for arg_name, arg_value in valid_kwargs.items():
            expected_type = type_hints.get(arg_name, Any)
            if not isinstance(arg_value, expected_type) and expected_type is not Any:
                logger.error(
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

    @classmethod
    async def connect(cls, host: str, port: int) -> None:
        if not all((cls._login, cls._password, cls._content_path)):
            logger.warning("Login, password or content_path not set, abort connect")
            return

        cls._reader, cls._writer = await asyncio.open_connection(host, port)
        cls._is_connected = True

        cls._ear_task = asyncio.create_task(cls._ear())

    @classmethod
    def is_connected(cls) -> bool:
        return cls._is_auth and cls._is_connected

    @classmethod
    def get_auth_lp(cls) -> bool:
        return cls._viva_alp

    @classmethod
    def set_auth_lp(cls, value: bool) -> None:
        cls._viva_alp = value

    @classmethod
    def get_login(cls) -> Optional[str]:
        return cls._login

    @classmethod
    def set_login(cls, value: str) -> None:
        cls._login = value

    @classmethod
    def set_password(cls, value: str) -> None:
        cls._password = value

    @classmethod
    def set_up_content_path(cls, value: Path | str) -> None:
        cls._content_path = Path(value)
        cls._temp_fold = cls._content_path / "temp"
        cls._temp_fold.mkdir(exist_ok=True)

    @classmethod
    async def disconnect(cls) -> None:
        cls._is_connected = False

        if cls._writer:
            cls._writer.close()
            await cls._writer.wait_closed()

        if cls._ear_task:
            cls._ear_task.cancel()
            try:
                await cls._ear_task

            except asyncio.CancelledError:
                pass

        cls._writer = None
        cls._reader = None

        cls._is_auth = False

    @classmethod
    async def _ear(cls) -> None:
        while cls._is_connected:
            receive_packet = await cls._receive_packet()
            if not isinstance(receive_packet, dict):
                logger.error("From server data type expected dict")
                continue

            code = receive_packet.get("code", None)
            if not code:
                logger.error("From server data must has 'code' key")
                continue

            if not isinstance(code, int):
                logger.error("From server 'code' type expected int")
                continue

            if code == NetCode.REQ_NET:
                await cls._call_method(
                    receive_packet.get("type", None), **receive_packet
                )

            if code in (
                NetCode.REQ_LOG_DEBUG,
                NetCode.REQ_LOG_INFO,
                NetCode.REQ_LOG_WARNING,
                NetCode.REQ_LOG_ERROR,
            ):
                cls._log(code, receive_packet)

            elif code == NetCode.REQ_AUTH:
                cls._server_name = receive_packet.get(
                    "server_name", "Not_Set_Server_Name"
                )
                Path(cls._content_path / cls._server_name).mkdir(exist_ok=True)  # type: ignore
                await cls._auth()

            elif code == NetCode.REQ_FILE_DOWNLOAD:
                cls._download_file(receive_packet)

            elif code == NetCode.END_FILE_DOWNLOAD:
                cls._move_file(receive_packet)

            else:
                logger.error("Unknown 'code' type from server")

    @classmethod
    async def req_net(cls, type: str, **kwargs: Any) -> None:
        await cls.send_packet(NetCode.REQ_NET.value, type=type, **kwargs)

    @classmethod
    async def send_packet(cls, code: NCAnyType, **kwargs: Any) -> None:
        payload = {"code": code, **kwargs}

        await cls._send_raw(msgpack.packb(payload))  # type: ignore

    @classmethod
    async def _send_raw(cls, data: bytes) -> None:
        if cls._writer is None:
            raise ValueError("StreamWriter is not set")

        cls._writer.write(len(data).to_bytes(4, byteorder="big"))
        await cls._writer.drain()

        cls._writer.write(data)
        await cls._writer.drain()

    @classmethod
    async def _receive_packet(cls) -> Any:
        if not cls._reader:
            return

        data_size_bytes = await cls._reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, "big")

        packed_data = await cls._reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)

    @classmethod
    def _log(cls, code: NCLogType, receive_packet: dict) -> None:
        msg = receive_packet.get("message", "Not set")

        if code == NetCode.REQ_LOG_DEBUG.value:
            logger.debug(msg)

        elif code == NetCode.REQ_LOG_INFO.value:
            logger.info(msg)

        elif code == NetCode.REQ_LOG_WARNING.value:
            logger.warning(msg)

        elif code == NetCode.REQ_LOG_ERROR.value:
            logger.error(msg)

        else:
            logger.warning(f"Unknown code for log: {receive_packet}")

    @classmethod
    async def _auth(cls) -> None:
        if cls._viva_alp:
            await cls.send_packet(
                NetCode.ANSWER_AUTH_ALP.value, login=cls._login, password=cls._password
            )

        else:
            await cls.send_packet(
                NetCode.ANSWER_AUTH_REG.value, login=cls._login, password=cls._password
            )

    @classmethod
    def _download_file(cls, receive_packet: dict) -> None:
        try:
            file_name = receive_packet.get("file_name", None)
            chunk = receive_packet.get("chunk", None)

            if not chunk or file_name:
                return

            file_path: Path = cls._content_path / cls._temp_fold / file_name  # type: ignore

            with file_path.open("wb+") as file:
                file.write(chunk)

        except Exception as e:
            logger.error(f"Error receiving file: {e}")

    @classmethod
    def _move_file(cls, receive_packet: dict) -> None:
        file_name = receive_packet.get("file_name")
        if not file_name:
            return

        file_path: Path = cls._content_path / cls._temp_fold / file_name  # type: ignore
        if file_path.exists():
            path_serve = cls._content_path / cls._server_name / file_name  # type: ignore
            file_path.rename(path_serve)
