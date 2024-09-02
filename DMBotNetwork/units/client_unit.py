from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any

import msgpack

from ..utils import NCAnyType, NetCode


class ClientUnit:
    __slots__ = ["_login", "_writer", "_reader"]

    def __init__(self, login: str, writer: StreamWriter, reader: StreamReader) -> None:
        self._login: str = login
        self._writer: StreamWriter = writer
        self._reader: StreamReader = reader

    def __eq__(self, value: object) -> bool:
        if isinstance(value, str):
            return value == self._login

        elif isinstance(value, ClientUnit):
            return value._login == self._login

        return False

    def __hash__(self) -> int:
        return hash(self._login)

    @property
    def login(self) -> str:
        return self._login

    @login.setter
    def login(self, value: str) -> None:
        self._login = value

    @property
    def writer(self) -> StreamWriter:
        return self._writer

    @property
    def reader(self) -> StreamWriter:
        return self._reader

    # Net
    async def req_net(self, type: str, **kwargs: Any) -> None:
        await self.send_packet(NetCode.REQ_NET, type=type, **kwargs)

    # Logs
    async def log_debug(self, message: str) -> None:
        await self.send_packet(NetCode.REQ_LOG_DEBUG, message=message)

    async def log_info(self, message: str) -> None:
        await self.send_packet(NetCode.REQ_LOG_INFO, message=message)

    async def log_warning(self, message: str) -> None:
        await self.send_packet(NetCode.REQ_LOG_WARNING, message=message)

    async def log_error(self, message: str) -> None:
        await self.send_packet(NetCode.REQ_LOG_ERROR, message=message)

    # Send
    async def send_packet(self, code: NCAnyType, **kwargs: Any) -> None:
        payload = {"code": code, **kwargs}

        await self.send_raw(msgpack.packb(payload))

    async def send_raw(self, data: bytes) -> None:
        if self._writer is None:
            raise ValueError("StreamWriter is not set")

        self._writer.write(len(data).to_bytes(4, byteorder="big"))
        await self._writer.drain()

        self._writer.write(data)
        await self._writer.drain()

    # File send
    async def send_file(
        self, file_path: Path, file_name: str, chunk_size: int = 4096
    ) -> None:
        if self._writer is None:
            raise ValueError("StreamWriter is not set")

        try:
            with file_path.open("rb") as file:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break

                    await self.send_packet(
                        NetCode.REQ_FILE_DOWNLOAD, file_name=file_name, chunk=chunk
                    )

        except Exception as e:
            await self.log_error(f"Error sending file: {e}")

    # Receive
    async def _receive_packet(self) -> Any:
        data_size_bytes = await self._reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, "big")

        packed_data = await self._reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)

    # Kill
    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
