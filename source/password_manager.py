import os
import json
import hashlib
import getpass
import base64
from source.utils import generate_password, check_password_strength, have_i_been_pwned, generate_totp_secret, get_totp_token, verify_totp_token, derive_key_from_password, encrypt_data, decrypt_data

class PasswordManager:
    def __init__(self):
        self.data_file = "passwords.json"
        self.master_password_hash_file = "master_password.hash"
        self.salt_file = "salt.bin"
        self.totp_secret_file = "totp_secret.key"
        self.master_password = None
        self.passwords = {}
        self.salt = None
        self.totp_secret = None
        self.load_data()
    
    def load_data(self):
        if os.path.exists(self.master_password_hash_file):
            with open(self.master_password_hash_file, 'rb') as file:
                self.master_password = file.read()
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as file:
                self.salt = file.read()
        if os.path.exists(self.totp_secret_file):
            with open(self.totp_secret_file, 'rb') as file:
                self.totp_secret = file.read().decode()
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as file:
                self.passwords = json.load(file)
    
    def save_data(self):
        with open(self.data_file, 'w') as file:
            json.dump(self.passwords, file)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).digest()
    
    def set_master_password(self):
        password = getpass.getpass("Set a master password: ")
        password_confirm = getpass.getpass("Confirm master password: ")
        if password == password_confirm:
            self.master_password = self.hash_password(password)
            self.salt = os.urandom(16)
            self.totp_secret = generate_totp_secret()
            with open(self.master_password_hash_file, 'wb') as file:
                file.write(self.master_password)
            with open(self.salt_file, 'wb') as file:
                file.write(self.salt)
            with open(self.totp_secret_file, 'wb') as file:
                file.write(self.totp_secret.encode())
            print("Master password set successfully!")
            print(f"Your TOTP secret is: {self.totp_secret}")
        else:
            print("Passwords do not match. Try again.")
    
    def authenticate_master_password(self):
        if not os.path.exists(self.master_password_hash_file):
            self.set_master_password()
        else:
            for _ in range(3):
                password = getpass.getpass("Enter master password: ")
                if self.hash_password(password) == self.master_password:
                    if self.totp_secret is None:
                        print("No TOTP secret found, setting up a new one.")
                        self.totp_secret = generate_totp_secret()
                        with open(self.totp_secret_file, 'wb') as file:
                            file.write(self.totp_secret.encode())
                    token = input("Enter the TOTP code: ")
                    if verify_totp_token(self.totp_secret, token):
                        print("Authentication successful!")
                        return True
                    else:
                        print("Incorrect TOTP code. Try again.")
                else:
                    print("Incorrect password. Try again.")
            print("Authentication failed.")
            return False
    
    def add_password(self):
        website = input("Enter the website: ")
        username = input("Enter the username: ")
        password = getpass.getpass("Enter the password: ")
        if not password:
            password = generate_password()
            print(f"Generated password: {password}")
        password_strength = check_password_strength(password)
        print(f"Password strength: {password_strength}")
        if password_strength != "Strong":
            print("Consider using a stronger password.")
        key = derive_key_from_password(self.master_password.decode(), self.salt)
        encrypted_password = encrypt_data(password, key)
        self.passwords[website] = {"username": username, "password": encrypted_password.decode()}
        self.save_data()
        print("Password saved successfully!")
    
    def get_password(self):
        website = input("Enter the website: ")
        if website in self.passwords:
            password_data = self.passwords[website]
            key = derive_key_from_password(self.master_password.decode(), self.salt)
            decrypted_password = decrypt_data(password_data["password"], key)
            print(f"Website: {website}\nUsername: {password_data['username']}\nPassword: {decrypted_password}")
            pwned_count = have_i_been_pwned(decrypted_password)
            if pwned_count:
                print(f"Warning: This password has been found {pwned_count} times in data breaches.")
        else:
            print("No password found for this website.")
    
    def update_password(self):
        website = input("Enter the website: ")
        if website in self.passwords:
            username = input("Enter the new username (leave blank to keep current): ")
            password = getpass.getpass("Enter the new password (leave blank to keep current): ")
            if username:
                self.passwords[website]["username"] = username
            if password:
                key = derive_key_from_password(self.master_password.decode(), self.salt)
                self.passwords[website]["password"] = encrypt_data(password, key).decode()
            self.save_data()
            print("Password updated successfully!")
        else:
            print("No password found for this website.")
    
    def delete_password(self):
        website = input("Enter the website: ")
        if website in self.passwords:
            del self.passwords[website]
            self.save_data()
            print("Password deleted successfully!")
        else:
            print("No password found for this website.")
    
    def view_all_passwords(self):
        if self.passwords:
            for website, data in self.passwords.items():
                key = derive_key_from_password(self.master_password.decode(), self.salt)
                decrypted_password = decrypt_data(data["password"], key)
                print(f"Website: {website}\nUsername: {data['username']}\nPassword: {decrypted_password}")
        else:
            print("No passwords stored.")
    
    def run(self):
        if self.authenticate_master_password():
            while True:
                print("\nPassword Manager")
                print("1. Add password")
                print("2. Get password")
                print("3. Update password")
                print("4. Delete password")
                print("5. View all passwords")
                print("6. Exit")
                choice = input("Choose an option: ")
                if choice == "1":
                    self.add_password()
                elif choice == "2":
                    self.get_password()
                elif choice == "3":
                    self.update_password()
                elif choice == "4":
                    self.delete_password()
                elif choice == "5":
                    self.view_all_passwords()
                elif choice == "6":
                    break
                else:
                    print("Invalid choice. Try again.")

if __name__ == "__main__":
    manager = PasswordManager()
    manager.run()
