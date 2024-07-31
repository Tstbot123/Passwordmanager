import unittest
from source.password_manager import PasswordManager
import pyotp

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.manager = PasswordManager()
        self.manager.totp_secret = pyotp.random_base32()

    def test_hash_password(self):
        password = "test"
        hashed = self.manager.hash_password(password)
        self.assertEqual(len(hashed), 64)

    def test_encrypt_decrypt(self):
        key = self.manager.load_key()
        data = "test"
        encrypted = self.manager.encrypt(key, data)
        decrypted = self.manager.decrypt(key, encrypted)
        self.assertEqual(data, decrypted)

    def test_2fa_verification(self):
        totp = pyotp.TOTP(self.manager.totp_secret)
        token = totp.now()
        self.assertTrue(self.manager.verify_2fa())

    def test_generate_qr_code(self):
        self.manager.generate_qr_code()
        self.assertTrue(os.path.exists("totp_qr.png"))

if __name__ == '__main__':
    unittest.main()
