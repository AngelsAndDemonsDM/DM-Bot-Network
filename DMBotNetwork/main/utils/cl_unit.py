import asyncio
import json
from pathlib import Path

import aiofiles

from .response_code import ResponseCode


class ClUnit:
    __slots__ = ["login", "_reader", "_writer"]

    def __init__(
        self, login, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Инициализация объекта ClUnit.

        Args:
            login (str): Логин пользователя.
            reader (StreamReader): Асинхронный поток для чтения данных.
            writer (StreamWriter): Асинхронный поток для записи данных.
        """
        self.login = login
        self._reader = reader
        self._writer = writer

    def __eq__(self, value: object) -> bool:
        if isinstance(value, str):
            return value == self.login

        elif isinstance(value, ClUnit):
            return value.login == self.login

        else:
            return False

    def __hash__(self) -> int:
        return hash(self.login)

    @property
    def reader(self) -> asyncio.StreamReader:
        """Возвращает асинхронный поток для чтения данных.

        Returns:
            StreamReader: Поток для чтения данных.
        """
        return self._reader

    @property
    def writer(self) -> asyncio.StreamWriter:
        """Возвращает асинхронный поток для записи данных.

        Returns:
            StreamWriter: Поток для записи данных.
        """
        return self._writer

    async def send_package(self, code: ResponseCode, **kwargs) -> None:
        """Отправка пакета данных.

        Args:
            code (ResponseCode): Код ответа для отправки.
            **kwargs: Дополнительные данные для передачи.
        """
        payload = {"code": code.value, **kwargs}
        en_data = self._encode_data(payload)
        await self._send_raw_data(en_data)

    async def receive_package(self) -> dict:
        """Получение и декодирование пакета данных.

        Returns:
            dict: Декодированные данные из пакета.
        """
        raw_data = await self._receive_raw_data()
        return self._decode_data(raw_data)

    async def send_file(
        self, file_path: Path | str, file_name: str, chunk_size: int = 8192
    ) -> None:
        """Асинхронная отправка файла по частям.

        Args:
            file_path (Path | str): Путь к файлу для отправки.
            file_name (str): Имя файла для отправки.
            chunk_size (int, optional): Размер блока для отправки файла. По умолчанию 8192 байт.

        Raises:
            ValueError: Если файл не существует или это не файл.
        """
        file_path = Path(file_path)

        if not file_path.exists() or not file_path.is_file():
            raise ValueError(
                "Invalid file_path. File doesn't exist or it is not a file."
            )

        async with aiofiles.open(file_path, "rb") as file:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    await self.send_package(ResponseCode.FIL_END, name=file_name)
                    break

                await self.send_package(
                    ResponseCode.FIL_REQ, name=file_name, chunk=chunk
                )

    async def send_log_debug(self, message: str) -> None:
        """Отправка сообщения с уровнем логирования DEBUG.

        Args:
            message (str): Сообщение для отправки.
        """
        await self.send_package(ResponseCode.LOG_DEB, message=message)

    async def send_log_info(self, message: str) -> None:
        """Отправка сообщения с уровнем логирования INFO.

        Args:
            message (str): Сообщение для отправки.
        """
        await self.send_package(ResponseCode.LOG_INF, message=message)

    async def send_log_warning(self, message: str) -> None:
        """Отправка сообщения с уровнем логирования WARNING.

        Args:
            message (str): Сообщение для отправки.
        """
        await self.send_package(ResponseCode.LOG_WAR, message=message)

    async def send_log_error(self, message: str) -> None:
        """Отправка сообщения с уровнем логирования ERROR.

        Args:
            message (str): Сообщение для отправки.
        """
        await self.send_package(ResponseCode.LOG_ERR, message=message)

    async def req_net_func(self, func_name: str, **kwargs) -> None:
        """Отправка запроса на выполнение сетевой функции.

        Args:
            func_name (str): Имя функции, которую нужно вызвать на сервере.
            **kwargs: Дополнительные аргументы для функции.
        """
        await self.send_package(ResponseCode.NET_REQ, net_func_name=func_name, **kwargs)

    def _encode_data(self, data: dict) -> bytes:
        """Кодирование данных в JSON-формат.

        Args:
            data (dict): Данные для кодирования.

        Returns:
            bytes: Закодированные данные в формате байт.
        """
        json_data = json.dumps(data, ensure_ascii=False)
        return json_data.encode("utf-8")

    def _decode_data(self, encoded_data: bytes) -> dict:
        """Декодирование данных из байт в JSON-формат.

        Args:
            encoded_data (bytes): Закодированные данные.

        Returns:
            dict: Декодированные данные в виде словаря.
        """
        json_data = encoded_data.decode("utf-8")
        return json.loads(json_data)

    async def _send_raw_data(self, data: bytes) -> None:
        """Асинхронная отправка сырых данных.

        Args:
            data (bytes): Данные для отправки.
        """
        self._writer.write(len(data).to_bytes(4, "big"))
        await self._writer.drain()

        self._writer.write(data)
        await self._writer.drain()

    async def _receive_raw_data(self) -> bytes:
        """Асинхронное получение сырых данных.

        Returns:
            bytes: Полученные данные в байтовом формате.
        """
        data_length_bytes = await self._reader.readexactly(4)
        data_length = int.from_bytes(data_length_bytes, "big")

        return await self._reader.readexactly(data_length)

    async def disconnect(self) -> None:
        """Отключение соединения."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()

            except ConnectionAbortedError:
                pass

            except Exception as err:
                raise err
