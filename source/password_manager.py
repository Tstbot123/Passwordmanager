import os
import json
import base64
import getpass
import hashlib
import pyotp
import qrcode
from cryptography.fernet import Fernet
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.master_password_hash = None
        self.data_file = "passwords.json"
        self.key_file = "key.key"
        self.totp_secret_file = "totp_secret.key"
        self.passwords = {}
        self.totp_secret = self.load_totp_secret()

    def load_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as file:
                file.write(key)
            return key

    def encrypt(self, key, data):
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())

    def decrypt(self, key, data):
        fernet = Fernet(key)
        return fernet.decrypt(data).decode()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def load_passwords(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, "r") as file:
                self.passwords = json.load(file)

    def save_passwords(self):
        with open(self.data_file, "w") as file:
            json.dump(self.passwords, file)

    def set_master_password(self):
        master_password = getpass.getpass("Set your master password: ")
        self.master_password_hash = self.hash_password(master_password)

    def verify_master_password(self):
        master_password = getpass.getpass("Enter your master password: ")
        return self.hash_password(master_password) == self.master_password_hash

    def load_totp_secret(self):
        if os.path.exists(self.totp_secret_file):
            with open(self.totp_secret_file, "r") as file:
                return file.read().strip()
        else:
            totp_secret = pyotp.random_base32()
            with open(self.totp_secret_file, "w") as file:
                file.write(totp_secret)
            return totp_secret

    def generate_qr_code(self):
        totp = pyotp.TOTP(self.totp_secret)
        uri = totp.provisioning_uri(name="PasswordManager", issuer_name="SecureApp")
        qr = qrcode.make(uri)
        qr.save("totp_qr.png")
        print("QR code for 2FA generated as totp_qr.png")

    def verify_2fa(self):
        totp = pyotp.TOTP(self.totp_secret)
        token = input("Enter the 2FA token: ")
        return totp.verify(token)

    def add_password(self):
        website = input("Enter the website: ")
        username = input("Enter the username: ")
        password = getpass.getpass("Enter the password: ")
        additional_info = input("Enter additional information (optional): ")
        key = self.load_key()
        encrypted_password = self.encrypt(key, password)
        self.passwords[website] = {
            "username": username,
            "password": encrypted_password.decode(),
            "additional_info": additional_info,
            "created_at": datetime.now().isoformat()
        }
        self.save_passwords()

    def view_passwords(self):
        key = self.load_key()
        for website, details in self.passwords.items():
            print(f"Website: {website}")
            print(f"Username: {details['username']}")
            print(f"Password: {self.decrypt(key, details['password'])}")
            print(f"Additional Info: {details['additional_info']}")
            print(f"Created At: {details['created_at']}")
            print("-" * 20)

    def run(self):
        self.load_passwords()
        if not self.master_password_hash:
            self.set_master_password()
        if not self.verify_master_password():
            print("Invalid master password!")
            return
        if not self.verify_2fa():
            print("Invalid 2FA token!")
            return

        while True:
            print("1. Add password")
            print("2. View passwords")
            print("3. Generate 2FA QR code")
            print("4. Exit")
            choice = input("Choose an option: ")

            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.view_passwords()
            elif choice == '3':
                self.generate_qr_code()
            elif choice == '4':
                break
            else:
                print("Invalid choice, please try again.")
