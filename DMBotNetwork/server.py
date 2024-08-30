import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional

import aiosqlite
import bcrypt
import msgpack

logger = logging.getLogger("DMBotNetwork Server")

class Server:
    _net_methods: Dict[str, Any] = {}
    _connects: Dict[str, StreamWriter] = {}
    _access_cache: Dict[str, Dict[str, bool]] = {}
    BASE_ACCESS: Dict[str, bool] = {}
    TIME_OUT: float = 30.0

    _host: Optional[str] = None
    _port: Optional[int] = None
    _server_name: Optional[str] = None
    _is_online: bool = False
    _connection: Optional[aiosqlite.Connection] = None
    _server: Optional[asyncio.AbstractServer] = None
    _db_path: Optional[Path] = None
    _owner_password: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        """Автоматически регистрирует методы, начинающиеся с 'net_', как сетевые методы."""
        super().__init_subclass__(**kwargs)
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("net_"):
                cls._net_methods[method[4:]] = getattr(cls, method)

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

    @classmethod
    async def start(cls) -> None:
        """Запускает сервер и начинает прослушивание входящих подключений."""
        if not cls._host or not cls._port or not cls._db_path:
            logger.error("Host, port, and database path must be set before starting the server.")
            return

        try:
            await cls._init_db()
            cls._is_online = True

            cls._server = await asyncio.start_server(cls._client_handle, cls._host, cls._port)

            async with cls._server:
                logger.info(f'Server started on {cls._host}:{cls._port}')
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

        for login, writer in cls._connects.items():
            await cls._close_connect(login, writer)

        cls._connects.clear()

        if cls._server:
            cls._server.close()
            await cls._server.wait_closed()

        if cls._connection:
            await cls._connection.close()

        logger.info('Server stopped.')

    @classmethod
    async def _init_db(cls) -> None:
        """Инициализирует базу данных, создавая необходимые таблицы, если они не существуют.
        Также добавляет пользователя 'owner' с полным доступом, если он отсутствует."""
        try:
            cls._connection = await aiosqlite.connect(cls._db_path / "server.db")
            await cls._connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT NOT NULL PRIMARY KEY,
                    password BLOB NOT NULL,
                    access BLOB NOT NULL
                )
            """)
            await cls._connection.commit()

            if not await cls._user_exists("owner"):
                owner_password_hashed = await cls._hash_password(cls._owner_password)
                await cls._connection.execute(
                    "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                    ("owner", owner_password_hashed, msgpack.packb({"full_access": True}))
                )
                await cls._connection.commit()

        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise

    @classmethod
    async def _user_exists(cls, username: str) -> bool:
        """Проверяет, существует ли пользователь в базе данных.

        Args:
            username (str): Имя пользователя для проверки.

        Returns:
            bool: True, если пользователь существует, иначе False.
        """
        try:
            async with cls._connection.execute("SELECT 1 FROM users WHERE username = ?", (username,)) as cursor:
                return await cursor.fetchone() is not None
        
        except Exception as e:
            logger.error(f"Error checking if user exists: {e}")
            return False

    @classmethod
    async def _check_password(cls, password: str, db_password: bytes) -> bool:
        """Проверяет соответствие пароля пользователя с хешем из базы данных.

        Args:
            password (str): Введенный пользователем пароль.
            db_password (bytes): Хеш пароля из базы данных.

        Returns:
            bool: True, если пароли совпадают, иначе False.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.checkpw, password.encode(), db_password)
    
    @classmethod
    async def _hash_password(cls, password: str) -> bytes:
        """Генерирует хеш пароля для безопасного хранения в базе данных.

        Args:
            password (str): Пароль для хеширования.

        Returns:
            bytes: Хеш пароля.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.hashpw, password.encode(), bcrypt.gensalt())

    @classmethod
    async def db_login_user(cls, login: str, password: str) -> Optional[str]:
        """Проверяет учетные данные пользователя и возвращает логин, если они верны.

        Args:
            login (str): Логин пользователя.
            password (str): Пароль пользователя.

        Returns:
            Optional[str]: Логин пользователя, если учетные данные верны, иначе None.
        """
        try:
            async with cls._connection.execute("SELECT password FROM users WHERE username = ?", (login,)) as cursor:
                row = await cursor.fetchone()

                if row and await cls._check_password(password, row[0]):
                    return login
                return None
        
        except Exception as e:
            logger.error(f"Error logging in user {login}: {e}")
            return None

    @classmethod
    async def db_add_user(cls, username: str, password: str, access: Dict[str, bool]) -> bool:
        """Добавляет нового пользователя в базу данных.

        Args:
            username (str): Логин нового пользователя.
            password (str): Пароль нового пользователя.
            access (Dict[str, bool]): Словарь прав доступа пользователя.

        Returns:
            bool: True, если пользователь успешно добавлен, иначе False.
        """
        hashed_password = await cls._hash_password(password)
        packed_access = msgpack.packb(access)
        try:
            await cls._connection.execute(
                "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                (username, hashed_password, packed_access)
            )
            await cls._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return False

    @classmethod
    async def db_get_access(cls, username: str) -> Optional[Dict[str, bool]]:
        """Возвращает права доступа пользователя.

        Args:
            username (str): Логин пользователя.

        Returns:
            Optional[Dict[str, bool]]: Словарь прав доступа пользователя, если он существует, иначе None.
        """
        if username in cls._access_cache:
            return cls._access_cache[username]
        
        async with cls._connection.execute("SELECT access FROM users WHERE username = ?", (username,)) as cursor:
            row = await cursor.fetchone()
            if row:
                access_data = msgpack.unpackb(row[0])
                cls._access_cache[username] = access_data
                return access_data
        
        return None

    @classmethod
    async def db_delete_user(cls, username: str) -> bool:
        """Удаляет пользователя из базы данных.

        Args:
            username (str): Логин пользователя для удаления.

        Returns:
            bool: True, если пользователь успешно удален, иначе False.
        """
        try:
            await cls._connection.execute("DELETE FROM users WHERE username = ?", (username,))
            await cls._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return False

    @classmethod
    async def db_change_password(cls, username: str, new_password: str) -> bool:
        """Изменяет пароль пользователя.

        Args:
            username (str): Логин пользователя.
            new_password (str): Новый пароль пользователя.

        Returns:
            bool: True, если пароль успешно изменен, иначе False.
        """
        hashed_password = await cls._hash_password(new_password)
        try:
            await cls._connection.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            await cls._connection.commit()
            cls._access_cache.pop(username, None)
            return True
        
        except Exception as e:
            logger.error(f"Error changing password for user {username}: {e}")
            return False

    @classmethod
    async def db_change_access(cls, username: str, new_access: Optional[Dict[str, bool]] = None) -> bool:
        """Изменяет права доступа пользователя.

        Args:
            username (str): Логин пользователя.
            new_access (Optional[Dict[str, bool]], optional): Новый словарь прав доступа. По умолчанию базовый словарь.

        Returns:
            bool: True, если права успешно изменены, иначе False.
        """
        if username == "owner":
            new_access = {"full_access": True}

        if not new_access:
            new_access = cls.BASE_ACCESS.copy()

        packed_access = msgpack.packb(new_access)

        try:
            await cls._connection.execute("UPDATE users SET access = ? WHERE username = ?", (packed_access, username))
            await cls._connection.commit()
            cls._access_cache.pop(username, None)
            return True
        
        except Exception as e:
            logger.error(f"Error changing access for user {username}: {e}")
            return False

    @classmethod
    async def check_access_login(cls, username: str, need_access: list[str]) -> bool:
        """Проверяет, есть ли у пользователя необходимые права доступа.

        Args:
            username (str): Логин пользователя.
            need_access (List[str]): Список прав, которые необходимо проверить.

        Returns:
            bool: True, если пользователь обладает всеми необходимыми правами, иначе False.
        """
        access_dict = await cls.db_get_access(username)
        return cls.check_access(access_dict, need_access) if access_dict else False
    
    @staticmethod
    def check_access(access_dict: Dict[str, bool], need_access: list[str]) -> bool:
        """Проверяет, имеет ли пользователь необходимые права.

        Args:
            access_dict (Dict[str, bool]): Словарь прав доступа пользователя.
            need_access (List[str]): Список прав, которые необходимо проверить.

        Returns:
            bool: True, если все права присутствуют, иначе False.
        """
        if access_dict.get("full_access", False):
            return True
        
        return all(access_dict.get(access, False) for access in need_access)
    
    @classmethod
    async def _req_auth(cls, reader: StreamReader, writer: StreamWriter) -> Optional[str]:
        """Запрашивает аутентификацию пользователя.

        Args:
            reader (StreamReader): Объект для чтения данных от клиента.
            writer (StreamWriter): Объект для отправки данных клиенту.

        Returns:
            Optional[str]: Логин пользователя, если аутентификация успешна, иначе None.
        """
        try:
            await cls.send_data(writer, {"req": "auth"})
            user_data = await asyncio.wait_for(cls._receive_data(reader), timeout=cls.TIME_OUT)

            if not isinstance(user_data, dict) or 'login' not in user_data or 'password' not in user_data:
                await cls.send_log(writer, "Invalid authentication data.", 'error')
                return None

            return await cls.db_login_user(user_data['login'], user_data['password'])

        except asyncio.TimeoutError:
            await cls.send_log(writer, "Timeout error.", 'error')
            return None

        except Exception as err:
            logger.error(f"Authentication error: {err}")
            await cls.send_log(writer, "Internal server error.", 'error')
            return None

    @classmethod
    async def _client_handle(cls, reader: StreamReader, writer: StreamWriter) -> None:
        """Основной цикл обработки запросов от клиента после успешной аутентификации."""
        login = await cls._req_auth(reader, writer)
        if not login:
            await cls._close_connect(writer=writer)
            return

        cls._connects[login] = writer
        logger.info(f"User '{login}' is connected")
        await cls.send_data(writer, {"action": "log", "log_type": "info", "msg": "Authentication successful."})

        try:
            while cls._is_online:
                user_data = await cls._receive_data(reader)
                if isinstance(user_data, dict):
                    action_type = user_data.get('action', None)
                    if action_type == "net":
                        answer = await cls._call_method(cls._net_methods, user_data.get('type'), user_login=login, **user_data)
                        await cls.send_data(writer, answer)
        
        except asyncio.IncompleteReadError as err:
            logger.info(f"Client connection closed: {err}")

        except ConnectionResetError as err:
            logger.info(f"Client reset the connection: {err}")

        except Exception as err:
            logger.error(f"Unexpected error from client: {err}")

        await cls._close_connect(login, writer)

    @classmethod
    async def _close_connect(cls, login: Optional[str] = None, writer: Optional[StreamWriter] = None) -> None:
        """Закрывает соединение с клиентом и удаляет его из списка активных подключений.

        Args:
            login (Optional[str], optional): Логин пользователя. Defaults to None.
            writer (Optional[StreamWriter], optional): Объект для отправки данных клиенту. Defaults to None.
        """
        if not login:
            for client_login, stored_writer in cls._connects.items():
                if writer and stored_writer == writer:
                    login = client_login
                    break

        if login in cls._connects:
            del cls._connects[login]

        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            
            except Exception as err:
                logger.error(f"Error closing connection for {login}: {err}")
        
        if login:
            logger.info(f"User '{login}' is disconnected")

    @classmethod
    async def send_log_login(cls, login: str, msg: str, log_type: str = 'info') -> None:
        await Server.send_data_login(login, {"action": "log", "log_type": log_type, "msg": msg})

    @classmethod
    async def send_log(cls, writer: StreamWriter, msg: str, log_type: str = 'info') -> None:
        await Server.send_data(writer, {"action": "log", "log_type": log_type, "msg": msg})
        
    @classmethod
    async def send_data_login(cls, login: str, data: Any) -> None:
        """Отправляет данные пользователю по его логину.

        Args:
            login (str): Логин пользователя.
            data (Any): Данные для отправки.

        Raises:
            ValueError: Если пользователь с указанным логином не подключен.
        """
        if login not in cls._connects:
            raise ValueError("Unknown login")

        await cls.send_data(cls._connects[login], data)

    @classmethod
    async def send_data(cls, writer: StreamWriter, data: Any) -> None:
        """Отправляет данные клиенту.

        Args:
            writer (StreamWriter): Объект для отправки данных клиенту.
            data (Any): Данные для отправки.
        """
        try:
            packed_data = msgpack.packb(data)
            await cls.send_raw(writer, packed_data)
        
        except Exception as e:
            logger.error(f"Error sending data: {e}")

    @classmethod
    async def broadcast_data(cls, data: Any) -> None:
        """Отправляет данные всем клиентам.

        Args:
            data (Any): Данные для отправки.
        """
        packed_data = msgpack.packb(data)
        tasks = []
        
        for _, writer in cls._connects.items():
            tasks.append(cls.send_raw(writer, packed_data))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    @classmethod
    async def send_raw(cls, writer: StreamWriter, data: bytes) -> None:
        """Отправляет сырые данные клиенту.

        Args:
            writer (StreamWriter): Объект для отправки данных клиенту.
            data (bytes): Данные для отправки.
        """
        try:
            writer.write(len(data).to_bytes(4, byteorder='big'))
            await writer.drain()

            writer.write(data)
            await writer.drain()
        except Exception as e:
            logger.error(f"Error sending data: {e}")

    @classmethod
    async def _receive_data(cls, reader: StreamReader) -> Any:
        """Получает данные от клиента.

        Args:
            reader (StreamReader): Объект для чтения данных от клиента.

        Returns:
            Any: Распакованные данные или None в случае ошибки.
        """
        data_size_bytes = await reader.readexactly(4)
        data_size = int.from_bytes(data_size_bytes, 'big')
        packed_data = await reader.readexactly(data_size)
        return msgpack.unpackb(packed_data)

    @classmethod
    async def _call_method(cls, metods_dict: Dict[str, Any], method_name: str, **kwargs) -> Any:
        """Вызывает зарегистрированный метод по его имени.

        Args:
            metods_dict (Dict[str, Any]): Словарь из которого будут вызываться методы.
            method_name (str): Имя метода для вызова.

        Returns:
            Any: Результат выполнения метода, если найден, иначе None.
        """
        method = metods_dict.get(method_name)
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
