from enum import IntEnum


class ResponseCode(IntEnum):
    # Авторизация
    AUTH_REQ = 10  # Запрос авторизации от сервера
    AUTH_ANS_LOGIN = 11  # Клиент отправляет запрос на авторизацию
    AUTH_ANS_REGIS = 12  # Клиент отправляет запрос на регистрацию
    AUTH_ANS_SERVE = 19  # Ответ сервера на регистрацию

    # Сетевые запросы
    NET_REQ = 20  # Запрос сетевого метода

    # Файловые операции
    FIL_REQ = 30  # Запрос на отправку фрагмента файла
    FIL_END = 31  # Завершение передачи файла

    # Логирование
    LOG_DEB = 41  # Запрос на отправку логов уровня DEBUG
    LOG_INF = 42  # Запрос на отправку логов уровня INFO
    LOG_WAR = 43  # Запрос на отправку логов уровня WARNING
    LOG_ERR = 44  # Запрос на отправку логов уровня ERROR

    # Методы для проверки типа кода
    @classmethod
    def is_auth(cls, code) -> bool:
        return code in {
            cls.AUTH_REQ,
            cls.AUTH_ANS_LOGIN,
            cls.AUTH_ANS_REGIS,
            cls.AUTH_ANS_SERVE,
        }

    @classmethod
    def is_client_auth(cls, code) -> bool:
        return code in {cls.AUTH_ANS_LOGIN, cls.AUTH_ANS_REGIS}

    @classmethod
    def is_net(cls, code) -> bool:
        return code == cls.NET_REQ

    @classmethod
    def is_file(cls, code) -> bool:
        return code in {cls.FIL_REQ, cls.FIL_END}

    @classmethod
    def is_log(cls, code) -> bool:
        return code in {cls.LOG_DEB, cls.LOG_INF, cls.LOG_WAR, cls.LOG_ERR}
