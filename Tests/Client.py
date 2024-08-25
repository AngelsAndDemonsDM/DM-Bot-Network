import shutil
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from DMBotNetwork.client import Client


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

    async def test_authenticate_success(self):
        with patch.object(Client, 'send_data', new_callable=AsyncMock), \
             patch.object(Client, 'receive_data', new_callable=AsyncMock) as mock_receive_data, \
             patch.object(Client, 'listen_for_messages', new_callable=AsyncMock) as mock_listen_for_messages:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "info", 'server_name': "dev_server"}

            Client._is_connected = True
            result = await Client._authenticate()
            Client._is_connected = False
            
            self.assertTrue(result)
            self.assertEqual(Client._cur_server_name, "dev_server")
            mock_listen_for_messages.assert_not_called()

    async def test_authenticate_failure(self):
        with patch.object(Client, 'send_data', new_callable=AsyncMock), \
             patch.object(Client, 'receive_data', new_callable=AsyncMock) as mock_receive_data:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "error"}
            
            Client._is_connected = True
            result = await Client._authenticate()
            Client._is_connected = False

            self.assertFalse(result)
            self.assertFalse(Client._is_connected)

if __name__ == '__main__':
    unittest.main()
