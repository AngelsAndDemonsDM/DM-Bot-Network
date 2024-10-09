import asyncio
import inspect
import logging
from collections.abc import Callable
from pathlib import Path
from typing import (Any, Dict, List, Optional, Type, Union, get_args,
                    get_origin, get_type_hints)

import aiohttp

from .utils import ClUnit, ResponseCode, ServerDB

logger = logging.getLogger("DMBN:Server")


class Server:
    _network_funcs: Dict[str, Callable] = {}
    _cl_units: Dict[str, ClUnit] = {}
    _server: Optional[asyncio.AbstractServer] = None
    _cl_units_lock = asyncio.Lock()

    _is_online: bool = False

    _host: str = ""
    _port: int = 0
    _server_name: str = "dev"
    _server_desc: str = "None"
    _server_tags: List[str] = []
    _server_additional_links: Dict[str, str] = {}

    _allow_registration: bool = True
    _timeout: float = 30.0
    _max_players: int = -1

    _hub_list: List[aiohttp.ClientSession] = []
    _update_task_time: float = 240
    _update_task_ref = None

    @classmethod
    def register_methods_from_class(cls, external_classes: Type | List[Type]) -> None:
        """Регистрация методов с префиксом 'net_' из внешнего класса."""
        if not isinstance(external_classes, list):
            external_classes = [external_classes]

        for external_class in external_classes:
            for name, func in inspect.getmembers(
                external_class, predicate=inspect.isfunction
            ):
                if name.startswith("net_"):
                    method_name = name[4:]
                    cls._network_funcs[method_name] = func
                    logger.debug(
                        f"Registered method '{name}' from {external_class.__name__} as '{method_name}'"
                    )

    @classmethod
    async def _call_func(
        cls,
        func_name: str,
        cl_unit: ClUnit,
        **kwargs,
    ) -> Any:
        func = cls._network_funcs.get(func_name)
        if func is None:
            logger.debug(f"Network func '{func_name}' not found.")
            return

        sig = inspect.signature(func)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}

        type_hints = get_type_hints(func)

        for arg_name, arg_value in valid_kwargs.items():
            expected_type = type_hints.get(arg_name, Any)
            if get_origin(expected_type) is Union:
                if not isinstance(arg_value, get_args(expected_type)):
                    await cl_unit.send_log_error(
                        f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                    )
                    return

            else:
                if not isinstance(arg_value, expected_type):
                    await cl_unit.send_log_error(
                        f"Type mismatch for argument '{arg_name}': expected {expected_type}, got {type(arg_value)}."
                    )
                    return

        try:
            if inspect.iscoroutinefunction(func):
                return await func(cl_unit=cl_unit, **valid_kwargs)

            else:
                return func(cl_unit=cl_unit, **valid_kwargs)

        except Exception as e:
            logger.error(f"Error calling method '{func_name}' in {cls.__name__}: {e}")

    @classmethod
    async def setup_server(
        cls,
        server_name: str,
        host: str,
        port: int,
        db_path: str | Path,
        init_owner_password: str,
        base_access: Dict[str, bool],
        allow_registration: bool,
        timeout: float,
        max_player: int = -1,  # inf
    ) -> None:
        cls._server_name = server_name
        cls._allow_registration = allow_registration
        cls._timeout = timeout
        cls._max_players = max_player

        ServerDB.set_db_path(db_path)
        ServerDB.set_owner_base_password(init_owner_password)
        ServerDB.set_base_access(base_access)

        cls._host = host
        cls._port = port

        cls._server = await asyncio.start_server(cls._cl_handler, host, port)
        logger.info(f"Server setup. Host: {host}, port:{port}.")

    @classmethod
    def get_timeout(cls) -> float:
        return cls._timeout

    @classmethod
    def set_timeout(cls, value: float) -> None:
        cls._timeout = value

    @classmethod
    def get_allow_registration(cls) -> bool:
        return cls._allow_registration

    @classmethod
    def set_allow_registration(cls, value: bool) -> None:
        cls._allow_registration = value

    @classmethod
    def get_players_count(cls) -> int:
        return len(cls._cl_units)

    @classmethod
    def get_max_players(cls) -> int:
        return cls._max_players

    @classmethod
    def set_max_players(cls, value: int) -> None:
        if value < -1:
            value = -1

        cls._max_players = value

    @classmethod
    async def set_server_desc(cls, value: str) -> None:
        cls._server_desc = value

        if cls._is_online:
            await cls._update_server_on_hubs({"desc": value})

    @classmethod
    async def set_server_tags(cls, value: List[str]) -> None:
        cls._server_tags = value

        if cls._is_online:
            await cls._update_server_on_hubs({"tags": value})

    @classmethod
    async def set_server_additional_links(cls, value: Dict[str, str]) -> None:
        cls._server_additional_links = value

        if cls._is_online:
            await cls._update_server_on_hubs({"additional_links": value})

    @classmethod
    def get_connections(cls) -> Dict[str, ClUnit]:
        """Изменете список - кастрирую"""
        return cls._cl_units

    @classmethod
    async def get_connects_with_access(
        cls, access: str | List[str]
    ) -> Dict[str, ClUnit]:
        if isinstance(access, str):
            access = [access]

        return_dict: Dict[str, ClUnit] = {}

        tasks = [
            (login, ServerDB.check_access_login(login, access))
            for login in cls._cl_units.keys()
        ]

        results = await asyncio.gather(*[task[1] for task in tasks])

        for (login, _), result in zip(tasks, results):
            if result:
                return_dict[login] = cls._cl_units[login]

        return return_dict

    @classmethod
    async def start(cls) -> None:
        if not cls._server:
            raise RuntimeError("Server is not initialized")

        if cls._is_online:
            raise RuntimeError("Server already active")

        await ServerDB.start()

        try:
            await cls._add_server_to_hubs()
            cls._start_update_task()

            async with cls._server:
                cls._is_online = True
                logger.info("Server start.")
                await cls._server.serve_forever()

        except asyncio.CancelledError:
            pass

        except Exception as err:
            logger.error(f"Error starting server: {err}")

        finally:
            if cls._is_online:
                await cls.stop()

    @classmethod
    async def stop(cls) -> None:
        if not cls._is_online:
            raise RuntimeError("Server is inactive")

        cls._is_online = False

        await cls._stop_update_task()

        await cls._delete_server_from_hubs()
        for hub in cls._hub_list:
            await hub.close()

        await asyncio.gather(
            *(
                cl_unit.disconnect("Server shutdown")
                for cl_unit in cls._cl_units.values()
            )
        )
        cls._cl_units.clear()

        if cls._server:
            cls._server.close()
            await cls._server.wait_closed()

        await ServerDB.stop()
        logger.info("Server stop.")

    @classmethod
    async def broadcast(
        cls,
        func_name: str,
        cl_units_dict: Optional[Dict[str, ClUnit]] = None,
        *args,
        **kwargs,
    ) -> None:
        tasks = []

        if cl_units_dict is None:
            cl_units_dict = cls._cl_units

        for cl_unit in cl_units_dict.values():
            func = getattr(cl_unit, func_name, None)
            if callable(func):
                tasks.append(func(*args, **kwargs))

            else:
                logger.error(f"{func_name} is not a callable method of {cl_unit}")

        if tasks:
            await asyncio.gather(*tasks)

    @classmethod
    async def remove_user(cls, login: str) -> None:
        await ServerDB.delete_user(login)
        cl_unit = cls._cl_units.get(login, None)

        if cl_unit is not None:
            await cl_unit.disconnect("Removed from server")

    @classmethod
    async def _cl_handler(
        cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cl_unit = ClUnit("init", reader, writer)

        if not cls._is_online:
            await cl_unit.disconnect("Server is inactive")
            return

        try:
            await cls._auth(cl_unit)

        except TimeoutError:
            await cl_unit.disconnect("Timeout for auth")
            return

        except ValueError as err:
            await cl_unit.disconnect(str(err))
            return

        except Exception as err:
            await cl_unit.disconnect(f"An unexpected error occurred: {err}")
            return

        async with cls._cl_units_lock:
            cls._cl_units[cl_unit.login] = cl_unit

        logger.info(f"{cl_unit.login} is connected")

        try:
            while cls._is_online:
                try:
                    receive_package = await cl_unit.receive_package()
                    if not isinstance(receive_package, dict):
                        await cl_unit.send_log_error("Receive data type expected dict")
                        continue

                    code = receive_package.pop("code", None)
                    if not code:
                        await cl_unit.send_log_error("Receive data must has 'code' key")
                        continue

                    if code == ResponseCode.NET_REQ:
                        func_name = receive_package.pop("net_func_name", None)
                        await cls._call_func(
                            func_name,
                            cl_unit,
                            **receive_package,
                        )

                    elif code == ResponseCode.GET_REQ:
                        func_name = receive_package.pop("net_func_name", None)
                        get_key = receive_package.pop("net_get_key", None)
                        if get_key is None:
                            continue

                        data = await cls._call_func(
                            func_name,
                            cl_unit,
                            **receive_package,
                        )
                        await cl_unit.send_package(
                            ResponseCode.GET_REQ, get_key=get_key, data=data
                        )

                    else:
                        await cl_unit.send_log_error("Unknown 'code' for net type")

                except PermissionError as err:
                    await cl_unit.send_log_error(
                        f"Access error. Insufficient permissions for the following: {err}"
                    )

        except (
            asyncio.CancelledError,
            ConnectionAbortedError,
            asyncio.exceptions.IncompleteReadError,
            ConnectionResetError,
        ):
            pass

        except Exception as err:
            logger.exception(f"An unexpected error occurred: {err}")
            await cl_unit.send_log_error(f"An unexpected error occurred: {err}")

        finally:
            async with cls._cl_units_lock:
                cls._cl_units.pop(cl_unit.login, None)

            await cl_unit.disconnect()
            logger.info(f"{cl_unit.login} is disconected")
            await cls._update_server_on_hubs({"cur_players": len(cls._cl_units)})

    @classmethod
    async def _auth(cls, cl_unit: ClUnit) -> None:
        if cls._max_players != -1 and cls._max_players <= len(cls._cl_units):
            raise ValueError("Server is full")

        await cl_unit.send_package(ResponseCode.AUTH_REQ)
        receive_package = await asyncio.wait_for(
            cl_unit.receive_package(), cls._timeout
        )

        if not isinstance(receive_package, dict):
            raise ValueError("Receive data type expected dict")

        code = receive_package.get("code", None)
        if not code:
            raise ValueError("Receive data must has 'code' key")

        code = ResponseCode(code)

        if not ResponseCode.is_client_auth(code):
            raise ValueError("Unknown 'code' for auth type")

        login = receive_package.get("login", None)
        password = receive_package.get("password", None)
        if not all([login, password]):
            raise ValueError("Receive data must has 'login' and 'password' keys")

        if code == ResponseCode.AUTH_ANS_REGIS:
            if not cls._allow_registration:
                raise ValueError("Registration is not allowed")

            await ServerDB.add_user(login, password)
            cl_unit.login = login

        else:
            await ServerDB.login_user(login, password)
            cl_unit.login = login

        await cl_unit.send_package(
            ResponseCode.AUTH_ANS_SERVE, server_name=cls._server_name
        )
        await cls._update_server_on_hubs({"cur_players": len(cls._cl_units)})

    @classmethod
    async def add_hub(cls, url):
        hub = aiohttp.ClientSession(url)
        cls._hub_list.append(hub)

        if cls._is_online:
            data = {
                "ip": cls._host,
                "port": str(cls._port),
                "name": cls._server_name,
                "max_players": cls._max_players,
                "cur_players": len(cls._cl_units),
                "desc": cls._server_desc,
                "tags": cls._server_tags,
                "additional_links": cls._server_additional_links,
            }

            async with hub.post("/servers/add", json=data) as response:
                response_data = await response.json()
                if "token" in response_data:
                    hub.headers.update(
                        {"Authorization": f"Bearer {response_data['token']}"}
                    )

    @classmethod
    async def _add_server_to_hubs(cls) -> None:
        data = {
            "ip": cls._host,
            "port": str(cls._port),
            "name": cls._server_name,
            "max_players": cls._max_players,
            "cur_players": len(cls._cl_units),
            "desc": cls._server_desc,
            "tags": cls._server_tags,
            "additional_links": cls._server_additional_links,
        }

        for hub in cls._hub_list:
            async with hub.post("/servers/add/", json=data) as response:
                response_data = await response.json()
                if "token" in response_data:
                    hub.headers.update(
                        {"Authorization": f"Bearer {response_data['token']}"}
                    )

    @classmethod
    async def _update_server_on_hubs(cls, data: Dict[str, Any]) -> None:
        for hub in cls._hub_list:
            await hub.put(f"/servers/{cls._server_name}/update/", json=data)

    @classmethod
    async def _update_task_logic(cls) -> None:
        while cls._is_online:
            await cls._update_server_on_hubs({"cur_players": len(cls._cl_units)})
            await asyncio.sleep(cls._update_task_time)

    @classmethod
    def _start_update_task(cls):
        cls._update_task_ref = asyncio.create_task(cls._update_task_logic())

    @classmethod
    async def _stop_update_task(cls):
        if cls._update_task_ref is not None:
            cls._update_task_ref.cancel()
            try:
                await cls._update_task_ref

            except asyncio.CancelledError:
                pass

            cls._update_task_ref = None

    @classmethod
    async def _delete_server_from_hubs(cls) -> None:
        for hub in cls._hub_list:
            await hub.delete(f"/servers/{cls._server_name}/delete/")
