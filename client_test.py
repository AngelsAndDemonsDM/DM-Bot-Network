import asyncio
import logging

from DMBotNetwork import Client


async def main():
    Client.setup(
        login="owner",
        password="owner_password",
        use_registration=False,
        content_path="./client_path",
    )

    await Client.connect("localhost", 5000)
    await asyncio.sleep(2)
    await Client.req_net_func("ping")
    await asyncio.sleep(2)
    await Client.disconnect()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    asyncio.run(main())
