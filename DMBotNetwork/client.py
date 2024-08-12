import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from typing import Any, Dict, Optional

import msgpack


class Client:
    _net_methods: Dict[str, Any] = {}

    def __init__(self, host: str, port: int, login: str, password: str) -> None:
        """Инициализирует объект клиента с указанием хоста, порта, логина и пароля.

        Args:
            host (str): Хост сервера.
            port (int): Порт сервера.
            login (str): Логин для аутентификации.
            password (str): Пароль для аутентификации.
        """
        self._host = host
        self._port = port
        self._login = login
        self._password = password

        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None

        self._is_connected = False
        self._listen_task: Optional[asyncio.Task] = None

    def __init_subclass__(cls, **kwargs):
        """Автоматически регистрирует методы, начинающиеся с 'net_', как сетевые методы.

        Args:
            **kwargs: Дополнительные аргументы.
        """
        super().__init_subclass__(**kwargs)
        for method in dir(cls):
            if callable(getattr(cls, method)) and method.startswith("net_"):
                Client._net_methods[method[4:]] = getattr(cls, method)

    @classmethod
    async def _call_net_method(cls, method_name: str, **kwargs) -> Any:
        """Вызывает зарегистрированный сетевой метод.

        Args:
            method_name (str): Название сетевого метода.

        Returns:
            Any: Результат выполнения метода или None, если метод не найден.
        """
        method = cls._net_methods.get(method_name)
        if method is None:
            return None

        sig = inspect.signature(method)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        try:
            if inspect.iscoroutinefunction(method):
                return await method(cls, **valid_kwargs)
            else:
                return method(cls, **valid_kwargs)
        
        except Exception as e:
            logging.error(f"Error calling net method {method_name}: {e}")
            return None

    async def _connect(self) -> None:
        """Устанавливает соединение с сервером."""
        try:
            self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
            self._is_connected = True
        
        except Exception as e:
            logging.error(f"Error connecting to server: {e}")
            self._is_connected = False

    async def _close(self) -> None:
        """Закрывает соединение с сервером."""
        self._is_connected = False

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            
            except Exception as e:
                logging.error(f"Error closing connection: {e}")

        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass

    async def send_data(self, data: Any) -> None:
        """Отправляет данные на сервер.

        Args:
            data (Any): Данные для отправки.

        Raises:
            ConnectionError: Если соединение с сервером не установлено.
        """
        if not self._writer:
            raise ConnectionError("Not connected to server")

        try:
            packed_data = msgpack.packb(data)
            self._writer.write(len(packed_data).to_bytes(4, byteorder='big'))
            await self._writer.drain()

            self._writer.write(packed_data)
            await self._writer.drain()
        
        except Exception as e:
            logging.error(f"Error sending data: {e}")

    async def receive_data(self) -> Any:
        """Получает данные с сервера.

        Raises:
            ConnectionError: Если соединение с сервером не установлено.

        Returns:
            Any: Распакованные данные или None в случае ошибки.
        """
        if not self._reader:
            raise ConnectionError("Not connected to server")

        try:
            data_size_bytes = await self._reader.readexactly(4)
            data_size = int.from_bytes(data_size_bytes, 'big')

            packed_data = await self._reader.readexactly(data_size)

            return msgpack.unpackb(packed_data)
        
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            return None

    async def authenticate(self) -> bool:
        """Аутентифицирует клиента на сервере.

        Returns:
            bool: True, если аутентификация успешна, иначе False.
        """
        await self._connect()

        if not self._is_connected:
            return False

        auth_data = {
            "login": self._login,
            "password": self._password
        }

        try:
            await self.send_data(auth_data)
            response = await self.receive_data()

            if isinstance(response, dict) and response.get("action") == "log" and response.get("log_type") == "info":
                self._listen_task = asyncio.create_task(self.listen_for_messages())
                return True
            
            else:
                await self._close()
                return False
        
        except Exception as e:
            logging.error(f"Error during authentication: {e}")
            await self._close()
            return False

    async def request_net_method(self, net_type: str, **kwargs) -> Any:
        """Запрашивает выполнение сетевого метода на сервере.

        Args:
            net_type (str): Тип сетевого метода.

        Raises:
            ConnectionError: Если соединение с сервером не установлено.

        Returns:
            Any: Результат выполнения сетевого метода или None в случае ошибки.
        """
        if not self._writer:
            raise ConnectionError("Not connected to server")

        request_data = {
            "action": "net",
            "net_type": net_type,
            **kwargs
        }

        try:
            await self.send_data(request_data)
            return await self.receive_data()
        
        except Exception as e:
            logging.error(f"Error requesting net method {net_type}: {e}")
            return None

    async def listen_for_messages(self) -> None:
        """Слушает входящие сообщения от сервера и обрабатывает их."""
        while self._is_connected:
            try:
                server_data = await self.receive_data()
                if isinstance(server_data, dict):
                    action_type = server_data.get('action')
                    if action_type == 'net':
                        await Client._call_net_method(server_data.get('net_type'), **server_data)
                    else:
                        logging.warning(f"Unexpected action type from server: {action_type}")
            
            except Exception as e:
                logging.error(f"Error in listen_for_messages: {e}")
                await self._close()

    async def close_connection(self) -> None:
        """Закрывает соединение с сервером."""
        await self._close()
