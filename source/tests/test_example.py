"""Testbeispiel für Unittests"""
import os
import sys
import unittest
from source.passwordManager import PasswordManager

# Sicherstellen, dass der korrekte Pfad für den Import genutzt wird
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../source')))

class TestPasswordManagerAdvanced(unittest.TestCase):
    """Erweiterte Tests für den Password Manager."""

    def setUp(self) -> None:
        """Vorbereitung vor jedem Test."""
        self.manager: PasswordManager = PasswordManager()
        self.manager.masterPasswordHash = self.manager.hashPassword("master_password")
        self.manager.failedAttempts = 0
        self.manager.lockoutTime = 0

    def test_failed_attempts_lockout(self) -> None:
        """Testet die Sperrfunktion nach mehreren fehlgeschlagenen Anmeldeversuchen."""
        self.manager.failedAttempts = 4
        self.assertFalse(self.manager.verifyMasterpassword())
        self.assertTrue(self.manager.lockoutTime > 0)

    def test_load_totp_secret(self) -> None:
        """Testet das Laden und Generieren des TOTP-Secrets."""
        secret: str = self.manager.loadTotpsecret()
        self.assertTrue(len(secret) > 0)
        self.assertEqual(secret, self.manager.loadTotpsecret())

    def test_generate_qr_code(self) -> None:
        """Testet die Generierung eines QR-Codes für 2FA."""
        self.manager.generateQrcode()
        self.assertTrue(os.path.exists("totp_qr.png"))
        os.remove("totp_qr.png")

if __name__ == "__main__":
    unittest.main()
