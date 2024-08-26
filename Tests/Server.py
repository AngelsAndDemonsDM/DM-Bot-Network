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

        Server()
        
        Server.set_host('localhost')
        Server.set_port(5000)
        Server.set_db_path(self.db_path)
        
        Server.set_owner_password('test_owner_password')
        await Server._init_db()

    async def asyncTearDown(self):
        await Server.stop()
        shutil.rmtree(self.db_path)
        
    async def test_init_db(self):
        access = await Server.db_get_access('owner')
        self.assertIsNotNone(access)
        self.assertIn('full_access', access)
        self.assertTrue(access['full_access'])

    async def test_db_add_user(self):
        await Server.db_add_user('test_user', 'password123', {'read': True})
        access = await Server.db_get_access('test_user')
        self.assertIsNotNone(access)
        self.assertIn('read', access)
        self.assertTrue(access['read'])

    async def test_db_login_user(self):
        await Server.db_add_user('test_user', 'password123', {'read': True})
        login_result = await Server.db_login_user('test_user', 'password123')
        self.assertEqual(login_result, 'test_user')

        wrong_login_result = await Server.db_login_user('test_user', 'wrongpassword')
        self.assertIsNone(wrong_login_result)

    async def test_db_change_password(self):
        await Server.db_add_user('test_user', 'password123', {'read': True})
        await Server.db_change_password('test_user', 'newpassword123')
        login_result = await Server.db_login_user('test_user', 'newpassword123')
        self.assertEqual(login_result, 'test_user')

    async def test_db_change_access(self):
        await Server.db_add_user('test_user', 'password123', {'read': True})
        await Server.db_change_access('test_user', {'write': True})
        access = await Server.db_get_access('test_user')
        self.assertIsNotNone(access)
        self.assertIn('write', access)
        self.assertTrue(access['write'])
        self.assertNotIn('read', access)

    async def test_db_delete_user(self):
        await Server.db_add_user('test_user', 'password123', {'read': True})
        await Server.db_delete_user('test_user')
        access = await Server.db_get_access('test_user')
        self.assertIsNone(access)

if __name__ == '__main__':
    unittest.main()
