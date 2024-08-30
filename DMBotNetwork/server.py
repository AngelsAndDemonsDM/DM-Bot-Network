import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional

import msgpack

logger = logging.getLogger("DMBotNetwork Server main")


class Server:
    _net_methods: Dict[str, Any] = {}
    _connects: Dict[str, StreamWriter] = {}
    TIME_OUT: float = 30.0

    _host: Optional[str] = None
    _port: Optional[int] = None
    _server_name: Optional[str] = None
    _is_online: bool = False
    _server: Optional[asyncio.AbstractServer] = None

    _db_path: Optional[Path] = None
    _owner_password: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        """Автоматически регистрирует методы, начинающиеся с 'net_', как сетевые методы."""
        super().__init_subclass__(**kwargs)
        cls._net_methods = {
            method[4:]: getattr(cls, method)
            for method in dir(cls)
            if callable(getattr(cls, method)) and method.startswith("net_")
        }

    # Сеттеры
    @classmethod
    def set_host(cls, host: str) -> None:
        cls._host = host

    @classmethod
    def set_port(cls, port: int) -> None:
        cls._port = port

    @classmethod
    def set_server_name(cls, server_name: str) -> None:
        cls._server_name = server_name

    @classmethod
    def set_db_path(cls, db_path: Path) -> None:
        cls._db_path = db_path

    @classmethod
    def set_owner_password(cls, owner_password: str) -> None:
        cls._owner_password = owner_password

    # Запуск и остановка сервера
    @classmethod
    async def start(cls) -> None:
        """Запускает сервер и начинает прослушивание входящих подключений."""
        if not all([cls._host, cls._port, cls._db_path]):
            logger.error(
                "Host, port, and database path must be set before starting the server."
            )
            return

        try:
            await cls._init_db()
            cls._is_online = True
            cls._server = await asyncio.start_server(
                cls._client_handle, cls._host, cls._port
            )
            async with cls._server:
                logger.info(f"Server started on {cls._host}:{cls._port}")
                await cls._server.serve_forever()
        except asyncio.CancelledError:
            await cls.stop()
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            await cls.stop()

    @classmethod
    async def stop(cls) -> None:
        """Останавливает сервер и закрывает все активные подключения."""
        cls._is_online = False
        await asyncio.gather(
            *(
                cls._close_connect(login, writer)
                for login, writer in cls._connects.items()
            ),
            return_exceptions=True,
        )
        cls._connects.clear()
        if cls._server:
            cls._server.close()
            await cls._server.wait_closed()
        
        if cls._connection:
            await cls._connection.close()

        logger.info("Server stopped.")

    # Аутентификация и обработка запросов
    @classmethod
    async def _req_auth(
        cls, reader: StreamReader, writer: StreamWriter
    ) -> Optional[str]:
        """Запрашивает аутентификацию пользователя."""
        try:
            await cls.send_data(writer, {"req": "auth"})
            user_data = await asyncio.wait_for(
                cls._receive_data(reader), timeout=cls.TIME_OUT
            )

            if (
                not isinstance(user_data, dict)
                or "login" not in user_data
                or "password" not in user_data
            ):
                await cls.send_log(writer, "Invalid authentication data.", "error")
                return None

            return await cls.db_login_user(user_data["login"], user_data["password"])
        except asyncio.TimeoutError:
            await cls.send_log(writer, "Timeout error.", "error")
            return None
        except Exception as err:
            logger.error(f"Authentication error: {err}")
            await cls.send_log(writer, "Internal server error.", "error")
            return None

    @classmethod
    async def _client_handle(cls, reader: StreamReader, writer: StreamWriter) -> None:
        """Основной цикл обработки запросов от клиента после успешной аутентификации."""
        login = await cls._req_auth(reader, writer)
        if not login:
            await cls.send_data(writer, {"req": "connect", "status": 1})
            await cls._close_connect(writer=writer)
            return

        cls._connects[login] = writer
        logger.info(f"User '{login}' is connected")
        await cls.send_data(
            writer, {"req": "connect", "status": 0, "server_name": cls._server_name}
        )

        try:
            while cls._is_online:
                user_data = await cls._receive_data(reader)
                if isinstance(user_data, dict) and user_data.get("action") == "net":
                    answer = await cls._call_method(
                        cls._net_methods,
                        user_data.get("type"),
                        user_login=login,
                        **user_data,
                    )
                    await cls.send_data(writer, answer)
        except (asyncio.IncompleteReadError, ConnectionResetError) as err:
            logger.info(f"Client connection issue: {err}")
        except Exception as err:
            logger.error(f"Unexpected error from client: {err}")
        finally:
            await cls._close_connect(login, writer)

    @classmethod
    async def _close_connect(
        cls, login: Optional[str] = None, writer: Optional[StreamWriter] = None
    ) -> None:
        """Закрывает соединение с клиентом и удаляет его из списка активных подключений."""
        if not login:
            login = next(
                (user_login for user_login, w in cls._connects.items() if w == writer),
                None,
            )

        if login:
            cls._connects.pop(login, None)
            logger.info(f"User '{login}' is disconnected")

        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as err:
                logger.error(f"Error closing connection for {login}: {err}")

    # Отправка данных клиентам
    @classmethod
    async def send_log_login(cls, login: str, msg: str, log_type: str = "info") -> None:
        await cls.send_data_login(
            login, {"action": "log", "log_type": log_type, "msg": msg}
        )

    @classmethod
    async def send_log(
        cls, writer: StreamWriter, msg: str, log_type: str = "info"
    ) -> None:
        await cls.send_data(writer, {"action": "log", "log_type": log_type, "msg": msg})

    @classmethod
    async def send_data_login(cls, login: str, data: Any) -> None:
        """Отправляет данные пользователю по его логину."""
        if login not in cls._connects:
            raise ValueError("Unknown login")
        await cls.send_data(cls._connects[login], data)

    @classmethod
    async def send_data(cls, writer: StreamWriter, data: Any) -> None:
        """Отправляет данные клиенту."""
        try:
            packed_data = msgpack.packb(data)
            await cls.send_raw(writer, packed_data)
        
        except Exception as e:
            logger.error(f"Error sending data: {e}")

    @classmethod
    async def broadcast_data(cls, data: Any) -> None:
        """Отправляет данные всем клиентам."""
        packed_data = msgpack.packb(data)
        await asyncio.gather(
            *(cls.send_raw(writer, packed_data) for writer in cls._connects.values()),
            return_exceptions=True,
        )

    @classmethod
    async def send_raw(cls, writer: StreamWriter, data: bytes) -> None:
        """Отправляет сырые данные клиенту."""
        try:
            writer.write(len(data).to_bytes(4, byteorder="big"))
            await writer.drain()

            writer.write(data)
            await writer.drain()
        except Exception as e:
            logger.error(f"Error sending data: {e}")

    @classmethod
    async def _receive_data(cls, reader: StreamReader) -> Any:
        """Получает данные от клиента."""
        data_size_bytes = await reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, "big")
        packed_data = await reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)

    @classmethod
    async def _call_method(
        cls, methods_dict: Dict[str, Any], method_name: str, **kwargs
    ) -> Any:
        """Вызывает зарегистрированный метод по его имени."""
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
