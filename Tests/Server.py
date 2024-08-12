import shutil
import unittest
from pathlib import Path
from unittest import mock

import msgpack

from DMBotNetwork.server import Server


class TestServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db_path = Path("test_dir")
        self.db_path.mkdir(parents=True, exist_ok=True)

        self.server = Server('localhost', 8888, self.db_path, 'test_owner_password')
        await self.server._init_db()

    async def asyncTearDown(self):
        await self.server.stop()
        shutil.rmtree(self.db_path)
        
    async def test_init_db(self):
        access = await self.server.db_get_access('owner')
        self.assertIsNotNone(access)
        self.assertIn('full_access', access)
        self.assertTrue(access['full_access'])

    async def test_db_add_user(self):
        await self.server.db_add_user('test_user', 'password123', {'read': True})
        access = await self.server.db_get_access('test_user')
        self.assertIsNotNone(access)
        self.assertIn('read', access)
        self.assertTrue(access['read'])

    async def test_db_login_user(self):
        await self.server.db_add_user('test_user', 'password123', {'read': True})
        login_result = await self.server.db_login_user('test_user', 'password123')
        self.assertEqual(login_result, 'test_user')

        wrong_login_result = await self.server.db_login_user('test_user', 'wrongpassword')
        self.assertIsNone(wrong_login_result)

    async def test_db_change_password(self):
        await self.server.db_add_user('test_user', 'password123', {'read': True})
        await self.server.db_change_password('test_user', 'newpassword123')
        login_result = await self.server.db_login_user('test_user', 'newpassword123')
        self.assertEqual(login_result, 'test_user')

    async def test_db_change_access(self):
        await self.server.db_add_user('test_user', 'password123', {'read': True})
        await self.server.db_change_access('test_user', {'write': True})
        access = await self.server.db_get_access('test_user')
        self.assertIsNotNone(access)
        self.assertIn('write', access)
        self.assertTrue(access['write'])
        self.assertNotIn('read', access)

    async def test_db_delete_user(self):
        await self.server.db_add_user('test_user', 'password123', {'read': True})
        await self.server.db_delete_user('test_user')
        access = await self.server.db_get_access('test_user')
        self.assertIsNone(access)

    async def test_send_receive_data(self):
        writer = mock.Mock()
        reader = mock.Mock()

        writer.write = mock.Mock()
        writer.drain = mock.AsyncMock()

        data = {'key': 'value'}
        packed_data = msgpack.packb(data)
        
        reader.readexactly = mock.AsyncMock(side_effect=[
            len(packed_data).to_bytes(4, byteorder='big'),
            packed_data
        ])

        await self.server.send_data(writer, data)
        
        writer.write.assert_has_calls([
            mock.call(len(packed_data).to_bytes(4, byteorder='big')), 
            mock.call(packed_data)
        ])

        received_data = await self.server.receive_data(reader)
        self.assertEqual(received_data, data)
        
if __name__ == '__main__':
    unittest.main()
