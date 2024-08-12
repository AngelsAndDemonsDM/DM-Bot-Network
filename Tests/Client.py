import shutil
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from DMBotNetwork.client import Client


class TestClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_dir = Path("test_dir")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.client = Client('localhost', 12345, 'user', 'pass', self.test_dir)

    async def asyncTearDown(self):
        shutil.rmtree(self.test_dir)

    async def test_connect(self):
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open_connection:
            mock_open_connection.return_value = (AsyncMock(), AsyncMock())

            await self.client.connect()
            self.assertIsNotNone(self.client._reader)
            self.assertIsNotNone(self.client._writer)

    async def test_authenticate_success(self):
        with patch.object(self.client, 'connect', new_callable=AsyncMock), \
             patch.object(self.client, 'send_data', new_callable=AsyncMock), \
             patch.object(self.client, 'receive_data', new_callable=AsyncMock) as mock_receive_data, \
             patch.object(self.client, 'listen_for_messages', new_callable=AsyncMock) as mock_listen_for_messages:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "info", 'server_name': "dev_server"}

            self.client._is_connected = True
            result = await self.client._authenticate()
            self.client._is_connected = False
            
            self.assertTrue(result)
            self.assertIsNotNone(self.client._listen_task)
            self.assertEqual(self.client._cur_server_name, "dev_server")
            mock_listen_for_messages.assert_called_once()

    async def test_authenticate_failure(self):
        with patch.object(self.client, 'connect', new_callable=AsyncMock), \
             patch.object(self.client, 'send_data', new_callable=AsyncMock), \
             patch.object(self.client, 'receive_data', new_callable=AsyncMock) as mock_receive_data:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "error"}
            
            self.client._is_connected = True
            result = await self.client._authenticate()
            self.client._is_connected = False

            self.assertFalse(result)
            self.assertFalse(self.client._is_connected)

if __name__ == '__main__':
    unittest.main()
