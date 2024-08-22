"""Hauptprogramm"""
import os
import re
import time
import json
import getpass
from datetime import datetime
from typing import Optional, Dict, Any, Union
import random
import string
import hashlib
import urllib.request
import qrcode
from cryptography.fernet import Fernet
import pyotp


class PasswordManager:
    """Hauptklasse"""
    def __init__(self) -> None:
        self.masterPasswordhash: Optional[str] = None
        self.dataFile: str = "passwords.json"
        self.keyFile: str = "key.key"
        self.masterPasswordfile: str = "master_password.hash"
        self.totpSecretfile: str = "totp_secret.key"
        self.passwords: Dict[str, Dict[str, Any]] = {}
        self.totpSecret: str = self.loadTotpsecret()
        self.failedAttempts: int = 0
        self.lockoutTime: float = 0
        self.loadMasterpassword()

    def loadMasterpassword(self) -> None:
        """Lädt den gespeicherten Master-Passwort-Hash, falls vorhanden."""
        if os.path.exists(self.masterPasswordfile):
            with open(self.master_password_file, "r", encoding="utf-8") as file:
                self.masterPasswordhash = file.read().strip()

    def saveMasterpassword(self) -> None:
        """Speichert den Master-Passwort-Hash in einer Datei."""
        if self.masterPasswordhash:
            with open(self.masterPasswordfile, "w", encoding="utf-8") as file:
                file.write(self.masterPasswordhash)

    def verifyMasterpassword(self) -> bool:
        """Überprüft das Master-Passwort und schützt vor Brute-Force-Angriffen."""
        if self.failedAttempts >= 5:
            remainingLockouttime = self.lockoutTime - time.time()
            if remainingLockouttime > 0:
                print(f"Too many failed attempts. Please try again in {int(remainingLockouttime)} seconds.")
                time.sleep(1)
                return False
            else:
                self.failedAttempts = 0
                self.lockoutTime = 0

        print("\n\033[91m" + "Enter your master password: " + "\033[37m")
        masterPassword = getpass.getpass()
        if self.hashPassword(masterPassword) == self.masterPasswordhash:
            self.failedAttempts = 0  # Zurücksetzen bei erfolgreicher Authentifizierung
            return True
        else:
            self.failedAttempts += 1
            if self.failedAttempts >= 5:
                self.lockoutTime = time.time() + (2 ** self.failedAttempts)
                print(f"Too many failed attempts. You are locked out for {int(self.lockoutTime - time.time())} seconds.")
            else:
                print(f"Invalid password. You have {5 - self.failedAttempts} attempts left.")
            return False

    def loadKey(self) -> bytes:
        """Lädt den Verschlüsselungsschlüssel oder erstellt einen neuen, wenn keiner existiert."""
        if os.path.exists(self.keyFile):
            with open(self.key_file, "rb") as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(self.keyFile, "wb") as file:
                file.write(key)
            return key

    def encrypt(self, key: bytes, data: str) -> bytes:
        """Verschlüsselt die Daten mit dem bereitgestellten Schlüssel."""
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())

    def decrypt(self, key: bytes, data: bytes) -> str:
        """Entschlüsselt die Daten mit dem bereitgestellten Schlüssel."""
        fernet = Fernet(key)
        return fernet.decrypt(data).decode()

    def hashPassword(self, password: str) -> str:
        """Hash das Passwort mit SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def loadPasswords(self) -> None:
        """Lädt gespeicherte Passwörter aus einer Datei."""
        if os.path.exists(self.dataFile):
            with open(self.data_file, "r", encoding="utf-8") as file:
                self.passwords = json.load(file)

    def savePasswords(self) -> None:
        """Speichert Passwörter in einer Datei."""
        with open(self.dataFile, "w", encoding="utf-8") as file:
            json.dump(self.passwords, file, indent=4)

    def setMasterpassword(self) -> None:
        """Setzt das Master-Passwort, wenn es noch nicht gesetzt ist."""
        masterPassword = getpass.getpass("Set your master password: ")
        self.masterPasswordhash = self.hashPassword(masterPassword)
        self.saveMasterpassword()

    def loadTotpsecret(self) -> str:
        """Lädt oder generiert das TOTP-Secret für die Zwei-Faktor-Authentifizierung."""
        if os.path.exists(self.totpSecretfile):
            with open(self.totp_secret_file, "r", encoding="utf-8") as file:
                return file.read().strip()
        else:
            totpSecret = pyotp.random_base32()
            with open(self.totpSecretfile, "w", encoding="utf-8") as file:
                file.write(totpSecret)
            return totpSecret

    def generateQrcode(self) -> None:
        """Generiert und speichert einen QR-Code für die Zwei-Faktor-Authentifizierung."""
        totp = pyotp.TOTP(self.totpSecret)
        uri = totp.provisioning_uri(name="PasswordManager", issuer_name="SecureApp")
        qr = qrcode.make(uri)
        qr.save("totp_qr.png")
        print("QR code for 2FA generated as totp_qr.png")

    def checkPasswordstrength(self, password: str) -> bool:
        """Überprüft die Stärke eines Passworts basierend auf Länge und Zeichensatz."""
        if len(password) < 8:
            print("\033[31m" + "Warning: Password is too short! Consider using at least 8 characters." + "\033[0m")
            return False

        if not re.search(r"[A-Z]", password):
            print("Warning: Password should contain at least one uppercase letter (A-Z).")
            return False

        if not re.search(r"[a-z]", password):
            print("Warning: Password should contain at least one lowercase letter (a-z).")
            return False

        if not re.search(r"\d", password):
            print("Warning: Password should contain at least one digit (0-9).")
            return False

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            print("Warning: Password should contain at least one special character (!@#$%^&* etc.).")
            return False

        return True

    def checkPasswordreuse(self, password: str) -> bool:
        """Überprüft, ob das neue Passwort bereits verwendet wird."""
        key = self.loadKey()
        for website, details in self.passwords.items():
            decryptedPassword = self.decrypt(key, details['password'].encode())
            if decryptedPassword == password:
                print(f"Warning: The password is already used for {website}. Consider using a unique password.")
                return True
        return False

    def checkPasswordbreach(self, password: str) -> bool:
        """Überprüft, ob das Passwort in bekannten Datenlecks vorkommt."""
        sha1Hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1Hash[:5]
        suffix = sha1Hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = urllib.request.urlopen(url)
            data = response.read().decode('utf-8')

            # Überprüfen, ob der Suffix im Antworttext vorhanden ist
            if suffix in data:
                print("\033[31m" + "Password has been pwned!" + "\033[0m")
                return True
            else:
                print("\033[32m" + "Password is safe!" + "\033[0m")
                return False

        except urllib.error.URLError as e:
            print(f"Failed to connect to Have I Been Pwned API: {e}")
            return False

    def generatePassword(
        self,
        length: int = 12,
        useUppercase: bool = True,
        useLowercase: bool = True,
        useDigits: bool = True,
        useSpecial: bool = True,
        excludeChars: str = '',
        enforcePattern: str = ''
    ) -> str:
        """Generiert ein sicheres Passwort basierend auf den angegebenen Kriterien."""
        charset = ''
        if useUppercase:
            charset += string.ascii_uppercase
        if useLowercase:
            charset += string.ascii_lowercase
        if useDigits:
            charset += string.digits
        if useSpecial:
            charset += string.punctuation

        if excludeChars:
            charset = ''.join(c for c in charset if c not in excludeChars)

        password = ''.join(random.choice(charset) for _ in range(length))

        if enforcePattern:
            if not re.search(enforcePattern, password):
                return self.generatePassword(length, useUppercase, useLowercase, useDigits, useSpecial, excludeChars, enforcePattern)

        return password

    def storePassword(self, website: str, username: str, password: str) -> None:
        """Speichert ein verschlüsseltes Passwort für eine Website."""
        key = self.loadKey()
        encryptedPassword = self.encrypt(key, password)
        self.passwords[website] = {
            "username": username,
            "password": encryptedPassword.decode(),
            "created": datetime.now().isoformat()
        }
        self.savePasswords()

    def retrievePassword(self, website: str) -> Optional[Dict[str, Union[str, datetime]]]:
        """Ruft das gespeicherte Passwort für eine Website ab."""
        key = self.loadKey()
        if website in self.passwords:
            details = self.passwords[website]
            decryptedPassword = self.decrypt(key, details['password'].encode())
            return {
                "username": details["username"],
                "password": decryptedPassword,
                "created": datetime.fromisoformat(details["created"])
            }
        else:
            print("No password found for this website.")
            return None


def main() -> None:
    """Main function zum starten"""
    passwordManager = PasswordManager()

    # Check if the master password is set, if not, set it
    if not passwordManager.masterPasswordhash:
        print("No master password found. Please set a master password.")
        passwordManager.setMasterpassword()

    if not passwordManager.verifyMasterpassword():
        return

    passwordManager.loadPasswords()

    while True:
        print("\nMenu:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Generate a new password")
        print("4. Check password strength")
        print("5. Check if password has been pwned")
        print("6. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")

            if passwordManager.checkPasswordreuse(password):
                print("The password is already in use. Please choose another one.")
                continue

            if not passwordManager.checkPasswordstrength(password):
                continue

            passwordManager.storePassword(website, username, password)
            print("Password stored successfully!")

        elif choice == "2":
            website = input("Enter the website: ")
            credentials = passwordManager.retrievePassword(website)
            if credentials:
                print(f"Username: {credentials['username']}")
                print(f"Password: {credentials['password']}")
                print(f"Created: {credentials['created']}")

        elif choice == "3":
            length = int(input("Enter the password length: "))
            useUppercase = input("Use uppercase letters? (y/n): ").lower() == 'y'
            useLowercase = input("Use lowercase letters? (y/n): ").lower() == 'y'
            useDigits = input("Use digits? (y/n): ").lower() == 'y'
            useSpecial = input("Use special characters? (y/n): ").lower() == 'y'
            excludeChars = input("Enter characters to exclude (leave blank for none): ")
            enforcePattern = input("Enter regex pattern to enforce (leave blank for none): ")

            password = passwordManager.generatePassword(
                length,
                useUppercase,
                useLowercase,
                useDigits,
                useSpecial,
                excludeChars,
                enforcePattern
            )
            print(f"Generated password: {password}")

        elif choice == "4":
            password = getpass.getpass("Enter the password to check strength: ")
            passwordManager.checkPasswordstrength(password)

        elif choice == "5":
            password = getpass.getpass("Enter the password to check if pwned: ")
            passwordManager.checkPasswordbreach(password)

        elif choice == "6":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
