import asyncio
import inspect
import logging
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Any, Dict, Optional

import msgpack

logger = logging.getLogger("DMBotNetwork Client")

class Client:
    _net_methods: Dict[str, Any] = {}

    def __init__(self, host: str, port: int, login: str, password: str, server_files_path: Path) -> None:
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
        self._server_file_path = server_files_path

        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None
        self._cur_server_name = None

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

    async def connect(self) -> None:
        """Устанавливает соединение с сервером."""
        try:
            self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
            self._is_connected = True
        
        except Exception as e:
            logger.error(f"Error connecting to server: {e}")
            self._is_connected = False

    async def _close(self) -> None:
        """Закрывает соединение с сервером."""
        self._is_connected = False

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            
            except Exception as e:
                logger.error(f"Error closing connection: {e}")

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
            logger.error(f"Error sending data: {e}")

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
            logger.error(f"Error receiving data: {e}")
            return None

    async def _authenticate(self) -> bool:
        """Аутентифицирует клиента на сервере.

        Returns:
            bool: True, если аутентификация успешна, иначе False.
        """
        auth_data = {
            "login": self._login,
            "password": self._password
        }

        try:
            await self.send_data(auth_data)
            response = await self.receive_data()

            if isinstance(response, dict) and response.get("action") == "log" and response.get("log_type") == "info":
                self._cur_server_name = response.get('server_name')
                self._listen_task = asyncio.create_task(self.listen_for_messages())
                return True
            
            else:
                await self._close()
                return False
        
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            await self._close()
            return False

    async def request_method(self, action: str, spec_type: str, **kwargs) -> Any:
        """Запрашивает выполнение метода на сервере.

        Args:
            action (str): Тип действия (net, download).
            spec_type (str): Указание метода который нужно вызвать

        Raises:
            ConnectionError: Если соединение с сервером не установлено.

        Returns:
            Any: Результат выполнения сетевого метода или None в случае ошибки.
        """
        if not self._writer:
            raise ConnectionError("Not connected to server")

        request_data = {
            "action": action,
            "type": spec_type,
            **kwargs
        }

        try:
            await self.send_data(request_data)
            return await self.receive_data()
        
        except Exception as e:
            logger.error(f"Error requesting method '{action}.{spec_type}'. kwargs: '{kwargs}'. Error: {e}")
            return None

    async def listen_for_messages(self) -> None:
        """Слушает входящие сообщения от сервера и обрабатывает их."""
        while self._is_connected:
            try:
                server_data = await self.receive_data()
                if isinstance(server_data, dict):
                    processors = {
                        'action': self._action_processor,
                        'req': self._req_processor
                    }
                    
                    for key, processor in processors.items():
                        data_type = server_data.get(key, None)
                        if data_type:
                            await processor(data_type, server_data)
                            break
            
            except Exception as e:
                logger.error(f"Error in listen_for_messages: {e}")
                await self._close()

    async def _req_processor(self, req_type, server_data: dict) -> None:
        if req_type == "auth":
            self._authenticate()
        
        elif req_type == "download":
            self._download_file(server_data)

        else:
            logger.warning(f"Unexpected action type from server: {req_type}")

    async def _action_processor(self, action_type, server_data: dict) -> None:
        if action_type == 'log':
            self.log_processor(server_data)
        
        elif action_type == 'net':
            await Client._call_method(self._net_methods, server_data.get('type'), **server_data)
        
        else:
            logger.warning(f"Unexpected action type from server: {action_type}")

    async def _download_file(self, server_data: dict) -> None:
        """Обрабатывает загрузку файла, получая его частями и сохраняя на диск."""
        file_size = server_data.get('file_size', None)
        if not file_size:
            return
        
        file_name = server_data.get('file_name', None)
        if not file_name:
            return
        
        dir_path = self._server_file_path / self._cur_server_name
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / file_name

        
        with open(file_path, "wb") as file:
            received_size = 0

            while received_size < file_size:
                chunk_data = await self.receive_data()
                
                file.write(chunk_data)
                received_size += len(chunk_data)

    def log_processor(self, server_data: dict) -> None:
        log_methods = {
            "info": logger.info,
            "warning": logger.warning,
            "error": logger.error,
            "debug": logger.debug,
            "critical": logger.critical,
        }
        log_type = server_data.get('log_type', 'not_set')
        log_method = log_methods.get(log_type)
        msg = server_data.get('msg', "empty")
        
        if log_method:
            log_method(msg)
        
        else:
            logger.warning(f"Unknown log_type: {log_type}. Message: {msg}")
    
    async def close_connection(self) -> None:
        """Закрывает соединение с сервером."""
        await self._close()
