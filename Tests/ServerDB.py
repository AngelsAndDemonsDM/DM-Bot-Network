import unittest
from pathlib import Path
from DMBotNetwork.main.utils.server_db import ServerDB

class TestServerDB(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_db_file: Path = Path("temp")
        self.temp_db_file.mkdir(exist_ok=True, parents=True)
        ServerDB.set_db_path(self.temp_db_file)
        await ServerDB.start()

    async def asyncTearDown(self):
        await ServerDB.stop()
        db_file = self.temp_db_file / "server.db"
        if db_file.exists():
            db_file.unlink()
        if self.temp_db_file.exists():
            self.temp_db_file.rmdir()

    async def test_add_user(self):
        await ServerDB.add_user("test_user", "password")
        self.assertIn("test_user", ServerDB._exist_user)
        await ServerDB.delete_user("test_user")

    async def test_delete_user(self):
        await ServerDB.add_user("test_user", "password")
        await ServerDB.delete_user("test_user")
        self.assertNotIn("test_user", ServerDB._exist_user)

    async def test_change_user_password(self):
        await ServerDB.add_user("test_user", "password")
        await ServerDB.change_user_password("test_user", "new_password")
        login = await ServerDB.login_user('test_user', 'new_password')
        self.assertEqual(login, 'test_user')
        await ServerDB.delete_user("test_user")

    async def test_get_access(self):
        await ServerDB.add_user("test_user", "password", {"some_access": True})
        access = await ServerDB.get_access("test_user")
        self.assertEqual(access, {"some_access": True})
        await ServerDB.delete_user("test_user")

    async def test_login_user(self):
        await ServerDB.add_user("test_user", "password")
        result = await ServerDB.login_user("test_user", "password")
        self.assertEqual(result, "test_user")
        await ServerDB.delete_user("test_user")

if __name__ == "__main__":
    unittest.main()
