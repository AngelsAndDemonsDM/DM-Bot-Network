from enum import Enum
from typing import Literal


class NetCode(Enum):
    REQ_AUTH: int = 10  # Запрос аунтификации
    ANSWER_AUTH_ALP: int = 11  # Ответ запроса аунтификации через логин пароль
    ANSWER_AUTH_REG: int = 12  # Ответ запроса регестрации

    REQ_NET: int = 20  # Запрос net метода клиента
    REQ_FILE_DOWNLOAD: int = 21
    END_FILE_DOWNLOAD: int = 22

    # Лог ивенты
    REQ_LOG_DEBUG: int = 30
    REQ_LOG_INFO: int = 31
    REQ_LOG_WARNING: int = 32
    REQ_LOG_ERROR: int = 33


NCReqType = Literal[10]
NCReqAnsewerType = Literal[11, 12]
NCReqNet = Literal[20]
NCLogType = Literal[30, 31, 32, 33]

NCAnyType = Literal[10, 11, 12, 20, 21, 22, 30, 31, 32, 33]
