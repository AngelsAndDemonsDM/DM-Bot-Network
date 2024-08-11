import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional

import aiosqlite
import bcrypt
import msgpack


class Server:
    _net_methods: Dict[str, Any] = {}
    _connects: Dict[str, StreamWriter] = {}

    BASE_ACCESS: Dict[str, bool] = {}

    TIME_OUT: float = 30.0

    def __init__(self, host: str, port: int, db_path: Path, owner_password: str = 'owner_password') -> None:
        self._host: str = host
        self._port: int = port
        self._is_online: bool = False

        self._connection: Optional[aiosqlite.Connection] = None
        self._server: Optional[asyncio.AbstractServer] = None

        self._db_path: Path = db_path
        self._owner_password: str = owner_password

    async def _init_db(self, db_path: Path, owner_password: str) -> None:
        self._connection = await aiosqlite.connect(db_path / "server.db")

        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT NOT NULL PRIMARY KEY,
                password BLOB NOT NULL,
                access BLOB NOT NULL
            )
        """)
        await self._connection.commit()

        async with self._connection.execute("SELECT username FROM users WHERE username = ?", ("owner",)) as cursor:
            row = await cursor.fetchone()

            if row is None:
                owner_password_hashed = await self._hash_password(owner_password)

                await self._connection.execute(
                    "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                    ("owner", owner_password_hashed, msgpack.packb({"full_access": True}))
                )
                await self._connection.commit()

    async def _check_password(self, password: str, db_password: bytes) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.checkpw, password.encode(), db_password)
    
    async def _hash_password(self, password: str) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.hashpw, password.encode(), bcrypt.gensalt())

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("net_"):
                Server._net_methods[method[4:]] = getattr(cls, method)

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

    # DB work
    async def db_login_user(self, login: str, password: str) -> Optional[str]:
        try:
            async with self._connection.execute("SELECT password FROM users WHERE username = ?", (login,)) as cursor:
                row = await cursor.fetchone()

                if row is None:
                    return None

                if await self._check_password(password, row[0]):
                    return login

                return None

        except Exception as e:
            logging.error(f"Error logging in user {login}: {e}")
            return None

    async def db_add_user(self, username: str, password: str, access: Dict[str, bool]) -> None:
        hashed_password = await self._hash_password(password)
        packed_access = msgpack.packb(access)
        try:
            await self._connection.execute(
                "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                (username, hashed_password, packed_access)
            )
            await self._connection.commit()
        except Exception as e:
            logging.error(f"Error adding user {username}: {e}")

    async def db_get_access(self, username: str) -> Optional[Dict[str, bool]]:
        try:
            async with self._connection.execute("SELECT access FROM users WHERE username = ?", (username,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return msgpack.unpackb(row[0])
                return None
        except Exception as e:
            logging.error(f"Error getting access for user {username}: {e}")
            return None

    async def db_delete_user(self, username: str) -> None:
        try:
            await self._connection.execute("DELETE FROM users WHERE username = ?", (username,))
            await self._connection.commit()
        except Exception as e:
            logging.error(f"Error deleting user {username}: {e}")

    async def db_change_password(self, username: str, new_password: str) -> None:
        hashed_password = await self._hash_password(new_password)
        try:
            await self._connection.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            await self._connection.commit()
        except Exception as e:
            logging.error(f"Error changing password for user {username}: {e}")

    async def db_change_access(self, username: str, new_access: Optional[Dict[str, bool]] = None) -> None:
        if username == "owner":
            new_access = {"full_access": True}

        if not new_access:
            new_access = self.BASE_ACCESS.copy()

        packed_access = msgpack.packb(new_access)

        try:
            await self._connection.execute("UPDATE users SET access = ? WHERE username = ?", (packed_access, username))
            await self._connection.commit()
        
        except Exception as e:
            logging.error(f"Error changing access for user {username}: {e}")

    # Client work
    async def _req_auth(self, reader: StreamReader, writer: StreamWriter) -> Optional[str]:
        try:
            await self.send_data(writer, {"action": "auth"})
            user_data = await asyncio.wait_for(self.receive_data(reader), timeout=self.TIME_OUT)

            if not isinstance(user_data, dict):
                await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Data must be a dictionary."})
                return None

            if 'login' not in user_data or 'password' not in user_data:
                await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Data must contain 'login' and 'password'."})
                return None

            return await self.db_login_user(user_data['login'], user_data['password'])

        except asyncio.TimeoutError:
            await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Timeout error."})
            return None

        except Exception as err:
            await self.send_data(writer, {"action": "log", "log_type": "error", "msg": f"Internal server error: {str(err)}"})
            return None

    async def _client_handle(self, reader: StreamReader, writer: StreamWriter) -> None:
        login = await self._req_auth(reader, writer)
        if not login:
            await self._close_connect(writer)
            return

        self._connects[login] = writer
        await self.send_data(writer, {"action": "log", "log_type": "info", "msg": "Authentication successful."})

        while self._is_online:
            user_data = await self.receive_data(reader)
            if isinstance(user_data, dict):
                action_type = user_data.get('action', None)
                if not action_type:
                    continue

                if action_type == "net":
                    answer = await Server._call_net_method(user_data.get('net_type'), user_login=login, **user_data)
                    await self.send_data(writer, answer)

        await self._close_connect(writer, login)

    async def _close_connect(self, writer: StreamWriter, login: Optional[str] = None) -> None:
        if login and login in self._connects:
            del self._connects[login]

        writer.close()
        await writer.wait_closed()

    # Data work
    # Via login
    async def send_data_login(self, login: str, data: Any) -> None:
        if login not in self._connects:
            raise ValueError("Unknown login")

        await self.send_data(self._connects[login], data)

    # Via writer
    async def send_data(self, writer: StreamWriter, data: Any) -> None:
        packed_data = msgpack.packb(data)
        writer.write(len(packed_data).to_bytes(4, byteorder='big'))
        await writer.drain()

        writer.write(packed_data)
        await writer.drain()

    async def receive_data(self, reader: StreamReader) -> Any:
        data_size_bytes = await reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, 'big')

        packed_data = await reader.readexactly(data_size)

        return msgpack.unpackb(packed_data)

    # Start/stop server
    async def start(self) -> None:
        await self._init_db(self._db_path, self._owner_password)

        self._is_online = True

        self._server = await asyncio.start_server(self._client_handle, self._host, self._port)

        async with self._server:
            logging.info(f'Server started on {self._host}:{self._port}')
            await self._server.serve_forever()

    async def stop(self) -> None:
        self._is_online = False

        for login, writer in self._connects.items():
            await self._close_connect(writer, login)

        self._connects.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        if self._connection:
            await self._connection.close()

        logging.info('Server stopped.')
