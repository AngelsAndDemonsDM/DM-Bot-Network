import unittest
from unittest.mock import AsyncMock, patch

from DMBotNetwork.client import Client


class TestClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = Client('localhost', 12345, 'user', 'pass')

    async def test_connect(self):
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open_connection:
            mock_open_connection.return_value = (AsyncMock(), AsyncMock())

            await self.client._connect()
            self.assertIsNotNone(self.client._reader)
            self.assertIsNotNone(self.client._writer)

    async def test_authenticate_success(self):
        with patch.object(self.client, '_connect', new_callable=AsyncMock), \
             patch.object(self.client, 'send_data', new_callable=AsyncMock), \
             patch.object(self.client, 'receive_data', new_callable=AsyncMock) as mock_receive_data, \
             patch.object(self.client, 'listen_for_messages', new_callable=AsyncMock) as mock_listen_for_messages:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "info"}

            self.client._is_connected = True
            result = await self.client.authenticate()
            self.client._is_connected = False
            
            self.assertTrue(result)
            self.assertIsNotNone(self.client._listen_task)
            mock_listen_for_messages.assert_called_once()

    async def test_authenticate_failure(self):
        with patch.object(self.client, '_connect', new_callable=AsyncMock), \
             patch.object(self.client, 'send_data', new_callable=AsyncMock), \
             patch.object(self.client, 'receive_data', new_callable=AsyncMock) as mock_receive_data:
            
            mock_receive_data.return_value = {"action": "log", "log_type": "error"}
            
            self.client._is_connected = True
            result = await self.client.authenticate()
            self.client._is_connected = False

            self.assertFalse(result)
            self.assertFalse(self.client._is_connected)

if __name__ == '__main__':
    unittest.main()
