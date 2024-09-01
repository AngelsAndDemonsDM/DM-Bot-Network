import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from typing import Any, Dict, Optional, get_type_hints

import msgpack
from utils import NetCode

logger = logging.getLogger("DMBotNetwork Client")


class Client:
    _network_methods: Dict[str, Any] = {}
    _ear_task: Optional[asyncio.Task] = None  # lol

    _login: str = None
    _password: str = None
    _is_downloaded: bool = True

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
    async def connect(cls, host, port) -> None:
        cls._reader, cls._writer = await asyncio.open_connection(host, port)
        cls._is_connected = True

        cls._ear_task = asyncio.create_task(cls._ear)

    @classmethod
    def is_connected(cls) -> bool:
        return cls._is_auth and cls._is_connected

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
                await cls._log()

            elif code == NetCode.REQ_AUTH:
                await cls._auth()

            elif code == NetCode.REQ_FILE_DOWNLOAD:
                await cls._download_file()

            elif code == NetCode.END_FILE_DOWNLOAD:
                cls._is_downloaded = True

            else:
                logger.error("Unknown 'code' type from server")

    @classmethod
    async def _receive_packet(cls) -> Any:
        data_size_bytes = await cls._reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, "big")

        packed_data = await cls._reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)

    # async def receive_file(self, file_path: Path) -> None:
    #    try:
    #        with file_path.open("wb") as file:
    #            while True:
    #                data_size_bytes = await self._reader.readexactly(4)
    #                data_size = int.from_bytes(data_size_bytes, "big")
    #
    #                if data_size == 0:
    #                    break
    #
    #                chunk = await self._reader.readexactly(data_size)
    #                file.write(chunk)
    #
    #    except Exception as e:
    #        await self.log_error(f"Error receiving file: {e}")
