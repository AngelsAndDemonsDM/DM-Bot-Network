from typing import List

from .cl_unit import ClUnit
from .server_db import ServerDB


def require_access(req_access: List[str] | str):
    """
    A decorator that ensures the user has the required access level(s) before executing the function.

    Args:
        req_access (List[str] | str): The required access level(s). Can be a single string or a list of strings 
                                      representing the access levels needed to execute the function.

    Returns:
        function: The decorated function that checks user access before execution.

    Raises:
        PermissionError: If the user does not have the necessary access permissions, 
                         this exception is raised with a message indicating the missing permissions.
    """
    
    if isinstance(req_access, str):
        req_access = [req_access]

    def decorator(func):
        async def wrapper(cl_unit: ClUnit, *args, **kwargs):
            if await ServerDB.check_access_login(cl_unit.login, req_access):
                return await func(cl_unit, *args, **kwargs)
            else:
                raise PermissionError(f"Access error. Insufficient permissions for the following: {'; '.join(req_access)}")

        return wrapper

    return decorator
