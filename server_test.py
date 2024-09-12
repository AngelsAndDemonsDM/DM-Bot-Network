import asyncio
import logging

from DMBotNetwork import ClUnit, Server


class NetClassPong:
    @staticmethod
    async def net_ping(cl_unit: ClUnit) -> None:
        await cl_unit.send_log_info(f"Pong, {cl_unit.login}!")


async def main():
    await Server.setup_server(
        server_name="test_server_name",
        host="localhost",
        port=5000,
        db_path="./test_db_path/",
        init_owner_password="owner_password",
        base_access={},
        allow_registration=False,
        timeout=5.0,
        max_player=5,
    )

    Server.register_methods_from_class(NetClassPong)

    await Server.start()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger1 = logging.getLogger("aiosqlite")
    logger1.propagate = False

    asyncio.run(main())
