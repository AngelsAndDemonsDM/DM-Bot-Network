import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite
import bcrypt
import msgpack

logger = logging.getLogger("DMBotNetwork Server")

class Server:
    _net_methods: Dict[str, Any] = {}
    _download_methods: Dict[str, Any] = {}
    _connects: Dict[str, Tuple[StreamReader, StreamWriter]] = {}
    BASE_ACCESS: Dict[str, bool] = {}
    TIME_OUT: float = 30.0

    def __init__(self, host: str, port: int, db_path: Path, owner_password: str = 'owner_password', server_name: str = "dev_server") -> None:
        """Инициализирует сервер с указанными параметрами.

        Args:
            host (str): Хост, на котором будет запущен сервер.
            port (int): Порт, на котором будет запущен сервер.
            db_path (Path): Путь к директории для хранения базы данных.
            owner_password (str, optional): Пароль владельца. По умолчанию 'owner_password'.
        """
        self._host = host
        self._port = port
        self._server_name = server_name
        
        self._is_online = False
        self._connection: Optional[aiosqlite.Connection] = None
        self._server: Optional[asyncio.AbstractServer] = None
        
        self._db_path = db_path
        self._owner_password = owner_password

    async def _init_db(self) -> None:
        """Инициализирует базу данных, создавая необходимые таблицы, если они не существуют.
        Также добавляет пользователя 'owner' с полным доступом, если он отсутствует."""
        try:
            self._connection = await aiosqlite.connect(self._db_path / "server.db")
            await self._connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT NOT NULL PRIMARY KEY,
                    password BLOB NOT NULL,
                    access BLOB NOT NULL
                )
            """)
            await self._connection.commit()

            if not await self._user_exists("owner"):
                owner_password_hashed = await self._hash_password(self._owner_password)
                await self._connection.execute(
                    "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                    ("owner", owner_password_hashed, msgpack.packb({"full_access": True}))
                )
                await self._connection.commit()

        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise

    async def _user_exists(self, username: str) -> bool:
        """Проверяет, существует ли пользователь в базе данных.

        Args:
            username (str): Имя пользователя для проверки.

        Returns:
            bool: True, если пользователь существует, иначе False.
        """
        try:
            async with self._connection.execute("SELECT 1 FROM users WHERE username = ?", (username,)) as cursor:
                return await cursor.fetchone() is not None
        
        except Exception as e:
            logger.error(f"Error checking if user exists: {e}")
            return False

    async def _check_password(self, password: str, db_password: bytes) -> bool:
        """Проверяет соответствие пароля пользователя с хешем из базы данных.

        Args:
            password (str): Введенный пользователем пароль.
            db_password (bytes): Хеш пароля из базы данных.

        Returns:
            bool: True, если пароли совпадают, иначе False.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.checkpw, password.encode(), db_password)
    
    async def _hash_password(self, password: str) -> bytes:
        """Генерирует хеш пароля для безопасного хранения в базе данных.

        Args:
            password (str): Пароль для хеширования.

        Returns:
            bytes: Хеш пароля.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, bcrypt.hashpw, password.encode(), bcrypt.gensalt())

    def __init_subclass__(cls, **kwargs):
        """Инициализация подклассов сервера. Автоматически регистрирует все методы, начинающиеся с 'net_' или с 'download_'."""
        super().__init_subclass__(**kwargs)
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("net_"):
                Server._net_methods[method[4:]] = getattr(cls, method)
        
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("download_"):
                Server._download_methods[method[9:]] = getattr(cls, method)

    @classmethod
    async def _call_method(cls, metods_dict: Dict[str, Any], method_name: str, **kwargs) -> Any:
        """Вызывает зарегистрированный метод по его имени.

        Args:
            metods_dict (Dict[str, Any]): Словарь из которого будут вызываться
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

    async def db_login_user(self, login: str, password: str) -> Optional[str]:
        """Проверяет учетные данные пользователя и возвращает логин, если они верны.

        Args:
            login (str): Логин пользователя.
            password (str): Пароль пользователя.

        Returns:
            Optional[str]: Логин пользователя, если учетные данные верны, иначе None.
        """
        try:
            async with self._connection.execute("SELECT password FROM users WHERE username = ?", (login,)) as cursor:
                row = await cursor.fetchone()

                if row and await self._check_password(password, row[0]):
                    return login
                return None
        
        except Exception as e:
            logger.error(f"Error logger in user {login}: {e}")
            return None

    async def db_add_user(self, username: str, password: str, access: Dict[str, bool]) -> bool:
        """Добавляет нового пользователя в базу данных.

        Args:
            username (str): Логин нового пользователя.
            password (str): Пароль нового пользователя.
            access (Dict[str, bool]): Словарь прав доступа пользователя.

        Returns:
            bool: True, если пользователь успешно добавлен, иначе False.
        """
        hashed_password = await self._hash_password(password)
        packed_access = msgpack.packb(access)
        try:
            await self._connection.execute(
                "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                (username, hashed_password, packed_access)
            )
            await self._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error adding user {username}: {e}")
            return False

    async def db_get_access(self, username: str) -> Optional[Dict[str, bool]]:
        """Возвращает права доступа пользователя.

        Args:
            username (str): Логин пользователя.

        Returns:
            Optional[Dict[str, bool]]: Словарь прав доступа пользователя, если он существует, иначе None.
        """
        try:
            async with self._connection.execute("SELECT access FROM users WHERE username = ?", (username,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return msgpack.unpackb(row[0])
                return None
        
        except Exception as e:
            logger.error(f"Error getting access for user {username}: {e}")
            return None

    async def db_delete_user(self, username: str) -> bool:
        """Удаляет пользователя из базы данных.

        Args:
            username (str): Логин пользователя для удаления.

        Returns:
            bool: True, если пользователь успешно удален, иначе False.
        """
        try:
            await self._connection.execute("DELETE FROM users WHERE username = ?", (username,))
            await self._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return False

    async def db_change_password(self, username: str, new_password: str) -> bool:
        """Изменяет пароль пользователя.

        Args:
            username (str): Логин пользователя.
            new_password (str): Новый пароль пользователя.

        Returns:
            bool: True, если пароль успешно изменен, иначе False.
        """
        hashed_password = await self._hash_password(new_password)
        try:
            await self._connection.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            await self._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error changing password for user {username}: {e}")
            return False

    async def db_change_access(self, username: str, new_access: Optional[Dict[str, bool]] = None) -> bool:
        """Изменяет права доступа пользователя.

        Args:
            username (str): Логин пользователя.
            new_access (Optional[Dict[str, bool]], optional): Новый словарь прав доступа. По умолчанию None.

        Returns:
            bool: True, если права успешно изменены, иначе False.
        """
        if username == "owner":
            new_access = {"full_access": True}

        if not new_access:
            new_access = self.BASE_ACCESS.copy()

        packed_access = msgpack.packb(new_access)

        try:
            await self._connection.execute("UPDATE users SET access = ? WHERE username = ?", (packed_access, username))
            await self._connection.commit()
            return True
        
        except Exception as e:
            logger.error(f"Error changing access for user {username}: {e}")
            return False

    async def check_access_login(self, username: str, need_access: List[str]) -> bool:
        """Проверяет, есть ли у пользователя необходимые права доступа.

        Args:
            username (str): Логин пользователя.
            need_access (List[str]): Список прав, которые необходимо проверить.

        Returns:
            bool: True, если пользователь обладает всеми необходимыми правами, иначе False.
        """
        access_dict = await self.db_get_access(username)
        return self.check_access(access_dict, need_access) if access_dict else False
    
    @staticmethod
    def check_access(access_dict: Dict[str, bool], need_access: List[str]) -> bool:
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
    
    async def _req_auth(self, reader: StreamReader, writer: StreamWriter) -> Optional[str]:
        """Запрашивает аутентификацию пользователя.

        Args:
            reader (StreamReader): Объект для чтения данных от клиента.
            writer (StreamWriter): Объект для отправки данных клиенту.

        Returns:
            Optional[str]: Логин пользователя, если аутентификация успешна, иначе None.
        """
        try:
            await self.send_data(writer, {"req": "auth"})
            user_data = await asyncio.wait_for(self.receive_data(reader), timeout=self.TIME_OUT)

            if not isinstance(user_data, dict) or 'login' not in user_data or 'password' not in user_data:
                await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Invalid authentication data.", 'server_name': self._server_name})
                return None

            return await self.db_login_user(user_data['login'], user_data['password'])

        except asyncio.TimeoutError:
            await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Timeout error."})
            return None

        except Exception as err:
            logger.error(f"Authentication error: {err}")
            await self.send_data(writer, {"action": "log", "log_type": "error", "msg": "Internal server error."})
            return None

    async def _client_handle(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Основной цикл обработки запросов от клиента после успешной аутентификации."""
        login = await self._req_auth(reader, writer)
        if not login:
            await self._close_connect(writer=writer)
            return

        self._connects[login] = (reader, writer)
        await self.send_data(writer, {"action": "log", "log_type": "info", "msg": "Authentication successful."})

        try:
            while self._is_online:
                user_data = await self.receive_data(reader)
                if isinstance(user_data, dict):
                    action_type = user_data.get('action', None)
                    if action_type == "net":
                        answer = await Server._call_method(self._net_methods, user_data.get('type'), user_login=login, **user_data)
                        await self.send_data(writer, answer)
                    
                    if action_type == "download":
                        await Server._call_method(self._download_methods, user_data.get('type'), user_login=login, **user_data)
        
        except Exception as e:
            logger.error(f"Error in client handling loop: {e}")

        await self._close_connect(login=login)

    async def _close_connect(self, login: Optional[str] = None, writer: Optional[StreamWriter] = None, reader: Optional[StreamReader] = None) -> None:
        """Закрывает соединение с клиентом и удаляет его из списка активных подключений.

        Args:
            login (Optional[str], optional): Логин пользователя. Defaults to None.
            writer (Optional[StreamWriter], optional): Объект для отправки данных клиенту. Defaults to None.
            reader (Optional[StreamReader], optional): Объект для чтения данных от клиента. Defaults to None.
        """
        if not login:
            for client_login, (stored_reader, stored_writer) in self._connects.items():
                if reader and stored_reader == reader:
                    login, writer = client_login, stored_writer
                    break
                elif writer and stored_writer == writer:
                    login = client_login
                    break

        if login in self._connects:
            del self._connects[login]

        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            
            except Exception as e:
                logger.error(f"Error closing connection for {login}: {e}")

    async def send_data_login(self, login: str, data: Any) -> None:
        """Отправляет данные пользователю по его логину.

        Args:
            login (str): Логин пользователя.
            data (Any): Данные для отправки.

        Raises:
            ValueError: Если пользователь с указанным логином не подключен.
        """
        if login not in self._connects:
            raise ValueError("Unknown login")

        await self.send_data(self._connects[login], data)

    async def send_file_login(self, login: str, path: Path, file_name: str) -> None:
        if login not in self._connects:
            raise ValueError("Unknown login")

        await self.send_file(self._connects[login], path, file_name)

    async def send_file(self, writer: StreamWriter, path: Path, file_name: str) -> None:
        """Отправляет файл пользователю через writer.

        Args:
            writer (StreamWriter): Поток, через который отправляются данные.
            path (Path): Путь файла, который надо отправить.
            file_name (str): Имя файла для передачи.

        Raises:
            Exception: В случае ошибки отправки данных.
        """
        try:
            file_size = path.stat().st_size

            file_info = {'req': 'download', 'file_size': file_size, 'file_name': file_name}
            await self.send_data(writer, file_info)

            with open(path, "rb") as file:
                while chunk := file.read(1024 * 1024):  # Чтение порции в 1 МБ
                    await self.send_data(writer, chunk)

        except Exception as e:
            logger.error(f"Error sending data: {e}")

    async def send_data(self, writer: StreamWriter, data: Any) -> None:
        """Отправляет данные клиенту.

        Args:
            writer (StreamWriter): Объект для отправки данных клиенту.
            data (Any): Данные для отправки.
        """
        try:
            packed_data = msgpack.packb(data)
            writer.write(len(packed_data).to_bytes(4, byteorder='big'))
            await writer.drain()

            writer.write(packed_data)
            await writer.drain()
        
        except Exception as e:
            logger.error(f"Error sending data: {e}")

    async def receive_data(self, reader: StreamReader) -> Any:
        """Получает данные от клиента.

        Args:
            reader (StreamReader): Объект для чтения данных от клиента.

        Returns:
            Any: Распакованные данные или None в случае ошибки.
        """
        try:
            data_size_bytes = await reader.readexactly(4)
            data_size = int.from_bytes(data_size_bytes, 'big')
            packed_data = await reader.readexactly(data_size)
            return msgpack.unpackb(packed_data)
        
        except asyncio.IncompleteReadError as e:
            logger.error(f"Client connection closed while receiving data: {e}")
            await self._close_connect(reader=reader)
            return None

        except ConnectionResetError as e:
            logger.error(f"Client reset the connection: {e}")
            await self._close_connect(reader=reader)
            return None

        except Exception as e:
            logger.error(f"Unexpected error receiving data from client: {e}")
            return None

    async def start(self) -> None:
        """Запускает сервер и начинает прослушивание входящих подключений."""
        try:
            await self._init_db()

            self._is_online = True

            self._server = await asyncio.start_server(self._client_handle, self._host, self._port)

            async with self._server:
                logger.info(f'Server started on {self._host}:{self._port}')
                await self._server.serve_forever()
        
        except asyncio.exceptions.CancelledError:
            await self.stop()
        
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            await self.stop()

    async def stop(self) -> None:
        """Останавливает сервер и закрывает все активные подключения."""
        self._is_online = False

        for login, writer in self._connects.items():
            await self._close_connect(writer, login)

        self._connects.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        if self._connection:
            await self._connection.close()

        logger.info('Server stopped.')
