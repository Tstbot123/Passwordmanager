"""Hauptdatei für Unittests"""
import unittest
import os
from source.passwordManager import PasswordManager

class TestPasswordManager(unittest.TestCase):
    """Testklasse des Passwordanagers"""

    def setUp(self) -> None:
        """Vorbereitung vor jedem Test."""
        self.manager = PasswordManager(username="test_user")#Username an Konstruktor
        self.manager.masterPasswordHash = self.manager.hashPassword("master_password")

        # Temporäre Dateien erstellen, um echte Dateien zu vermeiden
        self.manager.dataFile = "test_passwords.json"
        self.manager.keyFile = "test_key.key"
        self.manager.masterPasswordFile = "test_master_password.hash"
        self.manager.totpSecretFile = "test_totp_secret.key"

    def tearDown(self) -> None:
        """Aufräumen nach jedem Test."""
        if os.path.exists(self.manager.dataFile):
            os.remove(self.manager.dataFile)
        if os.path.exists(self.manager.keyFile):
            os.remove(self.manager.keyFile)
        if os.path.exists(self.manager.masterPasswordFile):
            os.remove(self.manager.masterPasswordFile)
        if os.path.exists(self.manager.totpSecretFile):
            os.remove(self.manager.totpSecretFile)

    def test_hashPassword(self) -> None:
        """Testet das Hashen des Master-Passworts."""
        password = "test_password"
        hashed = self.manager.hashPassword(password)
        self.assertEqual(hashed, self.manager.hashPassword(password))

    def test_encryptDecrypt(self) -> None:
        """Testet die Verschlüsselung und Entschlüsselung."""
        key = self.manager.loadKey()
        original_data = "secret_password"
        encrypted = self.manager.encrypt(key, original_data)
        decrypted = self.manager.decrypt(key, encrypted)
        self.assertEqual(original_data, decrypted)

    def test_addandRetrievepassword(self) -> None:
        """Testet das Hinzufügen und Abrufen eines Passworts."""
        self.manager.passwords = {}
        key = self.manager.loadKey()
        website = "example.com"
        username = "user"
        password = "password123"

        self.manager.passwords[website] = {
            "username": username,
            "password": self.manager.encrypt(key, password),
            "created_at": "2023-01-01T00:00:00"
        }
        self.manager.savePasswords()

        self.manager.loadPasswords()
        stored_password = self.manager.passwords[website]["password"]
        decrypted_password = self.manager.decrypt(key, stored_password)

        self.assertEqual(password, decrypted_password)

    def test_checkPasswordstrength(self) -> None:
        """Testet die Passwortstärkenprüfung."""
        weak_password = "short"
        strong_password = "Str0ngPassw@rd!"

        self.assertFalse(self.manager.checkPasswordstrength(weak_password))
        self.assertTrue(self.manager.checkPasswordstrength(strong_password))

if __name__ == "__main__":
    unittest.main()
