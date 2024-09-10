import json
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from .response_code import ResponseCode


class ClUnit:
    __slots__ = ["login", "_reader", "_writer"]

    def __init__(self, login, reader: StreamReader, writer: StreamWriter) -> None:
        self.login = login
        self._reader = reader
        self._writer = writer

    @property
    def reader(self) -> StreamReader:
        return self._reader

    @property
    def writer(self) -> StreamWriter:
        return self._writer

    async def send_pakage(self, code: ResponseCode, **kwargs) -> None:
        payload = {"code": code.value, **kwargs}
        en_data = self._encode_data(payload)
        await self._send_raw(en_data)

    async def send_file(self, file_path: Path | str) -> None:
        file_path = Path(file_path)
        
        if not file_path.exists() or not file_path.is_file():
            raise ValueError("Invalid file_path. File don't exists or it is not a file.")
        
        while True:
            pass

    def _encode_data(self, data: dict) -> bytes:
        json_data = json.dumps(data, ensure_ascii=False)
        return json_data.encode("utf-8")

    def _decode_data(self, encoded_data: bytes) -> dict:
        json_data = encoded_data.decode("utf-8")
        return json.loads(json_data)

    async def _send_raw(self, data: bytes) -> None:
        message_length = len(data)
        self._writer.write(message_length.to_bytes(4, "big") + data)
        await self._writer.drain()
