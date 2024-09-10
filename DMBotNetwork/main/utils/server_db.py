import asyncio
import logging
from pathlib import Path
from typing import Dict, Optional, Set

import aiosqlite
import bcrypt
import msgpack

logger = logging.getLogger("DMBN:ServerDB")


class ServerDB:
    _connection: Optional[aiosqlite.Connection] = None

    _access_cache: Dict[str, Dict[str, bool]] = {}
    _exist_user: Set[str] = set()

    _base_access: Dict[str, bool] = {}
    _db_path: Optional[Path] = None
    _owner_base_password: str = "owner_password"

    # Сеттеры и геттеры
    @classmethod
    def get_base_access(cls) -> Dict[str, bool]:
        return cls._base_access

    @classmethod
    def set_base_access(cls, value: Dict[str, bool]) -> None:
        cls._base_access = value

    @classmethod
    def get_db_path(cls) -> Optional[Path]:
        return cls._db_path

    @classmethod
    def set_db_path(cls, value: str | Path) -> None:
        cls._db_path = Path(value)

    @classmethod
    def get_owner_base_password(cls) -> str:
        return cls._owner_base_password

    @classmethod
    def set_owner_base_password(cls, value: str) -> None:
        cls._owner_base_password = value

    # Вспомогательное
    @classmethod
    def exist(cls, login: str) -> bool:
        return login in cls._exist_user

    # Инициализация БД
    @classmethod
    async def start(cls) -> None:
        await cls._init_db()
        await cls._init_exist_user()
        await cls._init_owner()

    @classmethod
    async def _init_db(cls) -> None:
        try:
            if cls._db_path is None:
                raise ValueError("Database path is not set.")

            cls._db_path.mkdir(parents=True, exist_ok=True)

            cls._connection = await aiosqlite.connect(cls._db_path / "server.db")
            await cls._connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT NOT NULL PRIMARY KEY,
                    password BLOB NOT NULL,
                    access BLOB NOT NULL
                )
            """)
            await cls._connection.commit()

        except Exception as err:
            logger.error(f"Error initializing database: {err}")
            raise

    @classmethod
    async def _init_exist_user(cls) -> None:
        if not cls._connection:
            logger.error("Connection not set")
            return

        try:
            async with cls._connection.execute("SELECT username FROM users") as cursor:
                rows = await cursor.fetchall()
                cls._exist_user = {row[0] for row in rows}

        except Exception as err:
            logger.error(f"Error initializing exist_user: {err}")
            raise

    @classmethod
    async def _init_owner(cls) -> None:
        if not cls._connection:
            logger.error("Connection not set")
            return

        try:
            if "owner" not in cls._exist_user:
                owner_password_hashed = await cls._hash_password(
                    cls._owner_base_password
                )

                await cls._connection.execute(
                    "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
                    (
                        "owner",
                        owner_password_hashed,
                        msgpack.packb({"full_access": True}),
                    ),
                )
                await cls._connection.commit()
                cls._exist_user.add("owner")

        except Exception as err:
            logger.error(f"Error initializing owner: {err}")
            raise

    @classmethod
    async def stop(cls) -> None:
        if cls._connection:
            await cls._connection.close()
            cls._connection = None

    # Работа с паролями
    @classmethod
    async def _check_password(cls, password: str, db_password: bytes) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, bcrypt.checkpw, password.encode(), db_password
        )

    @classmethod
    async def _hash_password(cls, password: str) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, bcrypt.hashpw, password.encode(), bcrypt.gensalt()
        )

    # Управление пользователями
    @classmethod
    async def login_user(cls, login: str, password: str) -> Optional[str]:
        if not cls._connection:
            logger.error("Connection not set")
            return

        if login not in cls._exist_user:
            raise ValueError(f"User '{login}' not found.")

        async with cls._connection.execute(
            "SELECT password FROM users WHERE username = ?", (login,)
        ) as cursor:
            row = await cursor.fetchone()

            if row is None:
                raise ValueError(f"User '{login}' not found in database.")

            if not await cls._check_password(password, row[0]):
                raise ValueError("Incorrect password.")

            return login

    @classmethod
    async def add_user(
        cls, username: str, password: str, access: Optional[Dict[str, bool]] = None
    ) -> None:
        if not cls._connection:
            logger.error("Connection not set")
            return

        if username in cls._exist_user:
            raise ValueError(f"User '{username}' already exists.")

        hashed_password = await cls._hash_password(password)

        if access is None:
            access = cls._base_access.copy()

        packed_access = msgpack.packb(access)

        await cls._connection.execute(
            "INSERT INTO users (username, password, access) VALUES (?, ?, ?)",
            (username, hashed_password, packed_access),
        )
        await cls._connection.commit()
        cls._exist_user.add(username)
        logger.info(f"User '{username}' successfully added.")

    @classmethod
    async def delete_user(cls, username: str) -> None:
        if not cls._connection:
            logger.error("Connection not set")
            return

        if username not in cls._exist_user:
            return

        await cls._connection.execute(
            "DELETE FROM users WHERE username = ?", (username,)
        )
        await cls._connection.commit()

        cls._access_cache.pop(username, None)
        cls._exist_user.discard(username)

    @classmethod
    async def change_user_password(cls, username: str, new_password: str) -> None:
        if not cls._connection:
            logger.error("Connection not set")
            return

        if username not in cls._exist_user:
            return

        hashed_password = await cls._hash_password(new_password)

        await cls._connection.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed_password, username),
        )

        await cls._connection.commit()

    @classmethod
    async def change_user_access(
        cls, username: str, new_access: Optional[Dict[str, bool]] = None
    ) -> bool:
        if not cls._connection:
            logger.error("Connection not set")
            return False

        if username not in cls._exist_user:
            return False

        if username == "owner":
            new_access = {"full_access": True}

        if not new_access:
            new_access = cls._base_access.copy()

        packed_access = msgpack.packb(new_access)

        try:
            await cls._connection.execute(
                "UPDATE users SET access = ? WHERE username = ?",
                (packed_access, username),
            )
            await cls._connection.commit()
            cls._access_cache.pop(username, None)
            return True

        except Exception as e:
            logger.error(f"Error changing access for user {username}: {e}")
            return False

    @classmethod
    async def get_access(cls, username: str) -> Optional[Dict[str, bool]]:
        if not cls._connection:
            logger.error("Connection not set")
            return None

        if username not in cls._exist_user:
            return None

        if username in cls._access_cache:
            return cls._access_cache[username]

        async with cls._connection.execute(
            "SELECT access FROM users WHERE username = ?", (username,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                access_data = msgpack.unpackb(row[0])
                cls._access_cache[username] = access_data
                return access_data

        return None

    # Работа с доступами
    @classmethod
    async def check_access_login(cls, username: str, need_access: list[str]) -> bool:
        access_dict = await cls.get_access(username)
        return cls.check_access(access_dict, need_access) if access_dict else False

    @staticmethod
    def check_access(access_dict: Dict[str, bool], need_access: list[str]) -> bool:
        if access_dict.get("full_access", False):
            return True

        return all(access_dict.get(access, False) for access in need_access)
