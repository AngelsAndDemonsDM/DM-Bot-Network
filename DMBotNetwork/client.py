import asyncio
import inspect
from asyncio import StreamReader, StreamWriter
from typing import Any, Dict, Optional

import msgpack


class Client:
    _net_methods: Dict[str, Any] = {}

    def __init__(self, host: str, port: int, login: str, password: str) -> None:
        self._host: str = host
        self._port: int = port
        self._login: str = login
        self._password: str = password

        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None

        self._is_connected: bool = False
        self._listen_task: Optional[asyncio.Task] = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("net_"):
                Client._net_methods[method[4:]] = getattr(cls, method)

    @classmethod
    async def _call_net_method(cls, method_name: str, **kwargs) -> Any:
        if method_name not in cls._net_methods:
            return None

        method = cls._net_methods[method_name]

        sig = inspect.signature(method)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        if inspect.iscoroutinefunction(method):
            return await method(cls, **valid_kwargs)
        else:
            return method(cls, **valid_kwargs)

    async def _connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)

    async def _close(self) -> None:
        self._is_connected = False

        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()

        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            
            except asyncio.CancelledError:
                pass

    async def send_data(self, data: Any) -> None:
        if not self._writer:
            raise ConnectionError("Not connected to server")

        packed_data = msgpack.packb(data)
        self._writer.write(len(packed_data).to_bytes(4, byteorder='big'))
        await self._writer.drain()

        self._writer.write(packed_data)
        await self._writer.drain()

    async def receive_data(self) -> Any:
        if not self._reader:
            raise ConnectionError("Not connected to server")

        data_size_bytes = await self._reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, 'big')

        packed_data = await self._reader.readexactly(data_size)

        return msgpack.unpackb(packed_data)

    async def authenticate(self) -> bool:
        await self._connect()

        auth_data = {
            "login": self._login,
            "password": self._password
        }

        await self.send_data(auth_data)

        response = await self.receive_data()
        if isinstance(response, dict) and response.get("action") == "log" and response.get("log_type") == "info":
            self._listen_task = asyncio.create_task(self.listen_for_messages())
            self._is_connected = True
            return True

        else:
            await self._close()
            return False

    async def request_net_method(self, net_type: str, **kwargs) -> Any:
        if not self._writer:
            raise ConnectionError("Not connected to server")

        request_data = {
            "action": "net",
            "net_type": net_type,
            **kwargs
        }

        await self.send_data(request_data)
        return await self.receive_data()

    async def listen_for_messages(self) -> None:
        while self._is_connected:
            server_data = await self.receive_data()

            if isinstance(server_data, dict):
                action_type = server_data.get('action', None)
                if not action_type:
                    raise ValueError(f"Unexpected answer from server: {server_data}")

                if action_type == 'net':
                    await Client._call_net_method(server_data.get('net_type'), **server_data)

    async def close_connection(self) -> None:
        await self._close()
