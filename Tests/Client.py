import shutil
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from DMBotNetwork.client import Client

# Bruh. No test

class TestClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_dir = Path("test_dir")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        Client.set_host("localhost")
        Client.set_port(12345)
        
        Client.set_login("user")
        Client.set_password("pass")
        
        Client.set_server_file_path(self.test_dir)

    async def asyncTearDown(self):
        shutil.rmtree(self.test_dir)

if __name__ == '__main__':
    unittest.main()
