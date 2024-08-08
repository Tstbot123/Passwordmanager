import unittest
from source.password_manager import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.pm = PasswordManager()
    
    def test_hash_password(self):
        password = "TestPassword"
        hashed_password = self.pm.hash_password(password)
        self.assertEqual(len(hashed_password), 32)
    
    def test_encrypt_decrypt(self):
        data = "TestData"
        encrypted_data = self.pm.encrypt_data(data)
        decrypted_data = self.pm.decrypt_data(encrypted_data)
        self.assertEqual(decrypted_data, data)

if __name__ == '__main__':
    unittest.main()
