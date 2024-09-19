from typing import List

from .cl_unit import ClUnit
from .server_db import ServerDB


def require_access(req_access: List[str] | str):
    if isinstance(req_access, str):
        req_access = [req_access]

    def decorator(func):
        async def wrapper(cl_unit: ClUnit, *args, **kwargs):
            if await ServerDB.check_access_login(cl_unit.login, req_access):
                return await func(cl_unit, *args, **kwargs)

            else:
                raise PermissionError(";".join(req_access))

        return wrapper

    return decorator
