import os
import re
import time
import json
import getpass
import random
import string
import hashlib
import urllib.request
import pyotp
import qrcode
from cryptography.fernet import Fernet
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.master_password_hash = None
        self.data_file = "passwords.json"
        self.key_file = "key.key"
        self.master_password_file = "master_password.hash"
        self.totp_secret_file = "totp_secret.key"
        self.passwords = {}
        self.totp_secret = self.load_totp_secret()
        self.failed_attempts = 0
        self.lockout_time = 0
        self.load_master_password()  # Lade das Master-Passwort beim Start

    def load_master_password(self):
        """Lädt den gespeicherten Master-Passwort-Hash, falls vorhanden."""
        if os.path.exists(self.master_password_file):
            with open(self.master_password_file, "r") as file:
                self.master_password_hash = file.read().strip()

    def save_master_password(self):
        """Speichert den Master-Passwort-Hash in einer Datei."""
        with open(self.master_password_file, "w") as file:
            file.write(self.master_password_hash)

    def verify_master_password(self):
        """Überprüft das Master-Passwort und schützt vor Brute-Force-Angriffen."""
        if self.failed_attempts >= 5:
            remaining_lockout_time = self.lockout_time - time.time()
            if remaining_lockout_time > 0:
                print(f"Too many failed attempts. Please try again in {int(remaining_lockout_time)} seconds.")
                time.sleep(1)
                return False
            else:
                self.failed_attempts = 0
                self.lockout_time = 0

        print("\n\033[91m" + "Enter your master password: " + "\033[37m")
        master_password = input()
        if self.hash_password(master_password) == self.master_password_hash:
            self.failed_attempts = 0  # Zurücksetzen bei erfolgreicher Authentifizierung
            return True
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= 5:
                self.lockout_time = time.time() + (2 ** self.failed_attempts)
                print(f"Too many failed attempts. You are locked out for {int(self.lockout_time - time.time())} seconds.")
            else:
                print(f"Invalid password. You have {5 - self.failed_attempts} attempts left.")
            return False

    def load_key(self):
        """Lädt den Verschlüsselungsschlüssel, oder erstellt einen neuen, wenn keiner existiert."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as file:
                file.write(key)
            return key

    def encrypt(self, key, data):
        """Verschlüsselt die Daten mit dem bereitgestellten Schlüssel."""
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())

    def decrypt(self, key, data):
        """Entschlüsselt die Daten mit dem bereitgestellten Schlüssel."""
        fernet = Fernet(key)
        return fernet.decrypt(data).decode()

    def hash_password(self, password):
        """Hash das Passwort mit SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def load_passwords(self):
        """Lädt gespeicherte Passwörter aus einer Datei."""
        if os.path.exists(self.data_file):
            with open(self.data_file, "r") as file:
                self.passwords = json.load(file)

    def save_passwords(self):
        """Speichert Passwörter in einer Datei."""
        with open(self.data_file, "w") as file:
            json.dump(self.passwords, file, indent=4)

    def set_master_password(self):
        """Setzt das Master-Passwort, wenn es noch nicht gesetzt ist."""
        master_password = getpass.getpass("Set your master password: ")
        self.master_password_hash = self.hash_password(master_password)
        self.save_master_password()

    def load_totp_secret(self):
        """Lädt oder generiert das TOTP-Secret für die Zwei-Faktor-Authentifizierung."""
        if os.path.exists(self.totp_secret_file):
            with open(self.totp_secret_file, "r") as file:
                return file.read().strip()
        else:
            totp_secret = pyotp.random_base32()
            with open(self.totp_secret_file, "w") as file:
                file.write(totp_secret)
            return totp_secret

    def generate_qr_code(self):
        """Generiert und speichert einen QR-Code für die Zwei-Faktor-Authentifizierung."""
        totp = pyotp.TOTP(self.totp_secret)
        uri = totp.provisioning_uri(name="PasswordManager", issuer_name="SecureApp")
        qr = qrcode.make(uri)
        qr.save("totp_qr.png")
        print("QR code for 2FA generated as totp_qr.png")

    def check_password_strength(self, password):
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

    def check_password_reuse(self, password):
        """Überprüft, ob das neue Passwort bereits verwendet wird."""
        key = self.load_key()
        for website, details in self.passwords.items():
            decrypted_password = self.decrypt(key, details['password'])
            if decrypted_password == password:
                print(f"Warning: The password is already used for {website}. Consider using a unique password.")
                return True
        return False

    def check_password_breach(self, password):
        """Überprüft, ob das Passwort in bekannten Datenlecks vorkommt."""
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = urllib.request.urlopen(url)
            data = response.read().decode('utf-8')

            # Überprüfen, ob der Suffix im Antworttext vorhanden ist
            if suffix in data:
                print("\033[31m" + "Password has been pwned!" + "\033[0m")
            else:
                print("\033[32m" + "Password is safe!" + "\033[0m")

        except urllib.error.URLError as e:
            print(f"Failed to connect to Have I Been Pwned API: {e}")

    def generate_password(self, length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True, exclude_chars='', enforce_pattern=''):
        """Generiert ein sicheres Passwort basierend auf den angegebenen Kriterien."""
        charset = ''
        if use_uppercase:
            charset += string.ascii_uppercase
        if use_lowercase:
            charset += string.ascii_lowercase
        if use_digits:
            charset += string.digits
        if use_special:
            charset += string.punctuation

        # Entfernen ausgeschlossener Zeichen
        charset = ''.join(ch for ch in charset if ch not in exclude_chars)

        if not charset:
            raise ValueError("Der Zeichensatz ist leer. Bitte passen Sie die Optionen an.")

        password = ''.join(random.choice(charset) for _ in range(length))

        # Erzwingen des Musters, falls angegeben
        if enforce_pattern and not re.match(enforce_pattern, password):
            raise ValueError(f"Das generierte Passwort erfüllt nicht das geforderte Muster: {enforce_pattern}")

        return password

    def generate_random_password(self):
        """Interaktive Funktion zum Generieren eines zufälligen Passworts."""
        length = self.prompt_for_length()
        use_uppercase = self.prompt_for_option("Include uppercase letters (A-Z)?")
        use_lowercase = self.prompt_for_option("Include lowercase letters (a-z)?")
        use_digits = self.prompt_for_option("Include digits (0-9)?")
        use_special = self.prompt_for_option("Include special characters (!@#$%^&*)?")
        exclude_chars = input("Enter characters to exclude (leave blank for none): ")

        try:
            password = self.generate_password(length=length, use_uppercase=use_uppercase, use_lowercase=use_lowercase, use_digits=use_digits, use_special=use_special, exclude_chars=exclude_chars)
            print(f"Generated Password: {password}")
        except ValueError as e:
            print(f"Error: {e}")


    def view_passwords(self):
        """Zeigt alle gespeicherten Passwörter an, oder filtert nach einer Suchanfrage."""
        search_query = input("Enter the website or username to search for (leave blank to view all): ").lower()
        print("\n")
        key = self.load_key()
        found = False

        for website, details in self.passwords.items():
            if not search_query or search_query in website.lower() or search_query in details['username'].lower():
                print(f"\nWebsite: {website}")
                print(f"Username: {details['username']}")
                print(f"Password: {self.decrypt(key, details['password'])}")
                print(f"Additional Info: {details['additional_info']}")
                print(f"Created At: {details['created_at']} \n")
                print("-" * 40)
                found = True

        if not found:
            if search_query:
                print(f"No passwords found for the search query: {search_query}")
            else:
                print("No passwords found.")

    def add_password(self):
        """Interaktive Funktion zum Hinzufügen eines neuen Passworts."""
        website = input("Enter the website: ")
        username = input("Enter the username: ")
    
        if self.prompt_for_option("Generate a random password?"):
            length = self.prompt_for_length()
            use_uppercase = self.prompt_for_option("Include uppercase letters (A-Z)?")
            use_lowercase = self.prompt_for_option("Include lowercase letters (a-z)?")
            use_digits = self.prompt_for_option("Include digits (0-9)?")
            use_special = self.prompt_for_option("Include special characters (!@#$%^&*)?")
            exclude_chars = input("Enter characters to exclude (leave blank for none): ")
    
            try:
                password = self.generate_password(length=length, use_uppercase=use_uppercase, use_lowercase=use_lowercase, use_digits=use_digits, use_special=use_special, exclude_chars=exclude_chars)
                print(f"Generated Password: {password}")
            except ValueError as e:
                print(f"Error: {e}")
                return  # Beendet die Funktion, wenn ein Fehler auftritt
        else:
            password = getpass.getpass("Enter the password: ")
        
        # Überprüfen der Passwortstärke
        if len(password) < 8:
            print("\033[31m" + "Warning: Password is too short! Consider using at least 8 characters." + "\033[0m")
            print("\033[31m" + "Consider choosing a stronger password." + "\033[0m")
            if not self.prompt_for_option("Do you want to continue with this password?"):
                return
    
        # Überprüfung auf Passwortverletzungen
        if self.check_password_breach(password):
            print("Warning: The password has been compromised in a data breach.")
            if not self.prompt_for_option("Do you want to continue with this password?"):
                return
    
        additional_info = input("Enter additional information (optional): ")
    
        key = self.load_key()
        encrypted_password = self.encrypt(key, password)
    
        # Wenn bereits ein Passwort für diese Website existiert, verschiebe es in den Verlauf
        if website in self.passwords:
            if "password_history" not in self.passwords[website]:
                self.passwords[website]["password_history"] = []
            old_password_entry = {
                "username": self.passwords[website]['username'],
                "password": self.passwords[website]['password'],
                "additional_info": self.passwords[website]['additional_info'],
                "created_at": self.passwords[website]['created_at'],
                "changed_at": datetime.now().isoformat()
            }
            self.passwords[website]["password_history"].append(old_password_entry)

        self.passwords[website] = {
            "username": username,
            "password": encrypted_password.decode(),
            "additional_info": additional_info,
            "created_at": datetime.now().isoformat()
        }
        self.save_passwords()

    def edit_password(self):
        """Ändert den Benutzernamen, das Passwort oder die zusätzlichen Informationen für eine gespeicherte Website."""
        website = input("Enter the website you want to edit: ")

        if website in self.passwords:
            key = self.load_key()

             # Speichern des alten Passworts in den Verlauf
            if "password_history" not in self.passwords[website]:
                self.passwords[website]["password_history"] = []
            old_password_entry = {
                "username": self.passwords[website]['username'],
                "password": self.passwords[website]['password'],
                "additional_info": self.passwords[website]['additional_info'],
                "created_at": self.passwords[website]['created_at'],
                "changed_at": datetime.now().isoformat()
            }
            self.passwords[website]["password_history"].append(old_password_entry)

            print(f"Current Username: {self.passwords[website]['username']}")
            new_username = input("Enter new username (leave blank to keep current): ")
            if new_username:
                self.passwords[website]['username'] = new_username

            print(f"Current Password: {self.decrypt(key, self.passwords[website]['password'])}")
            if self.prompt_for_option("Generate a new random password?"):
                new_password = self.generate_random_password()
            else:
                new_password = getpass.getpass("Enter new password (leave blank to keep current): ")
            if new_password:
                self.passwords[website]['password'] = self.encrypt(key, new_password).decode()

            print(f"Current Additional Info: {self.passwords[website]['additional_info']}")
            new_info = input("Enter new additional info (leave blank to keep current): ")
            if new_info:
                self.passwords[website]['additional_info'] = new_info

            self.save_passwords()
            print(f"Password for {website} has been updated.")
        else:
            print(f"No password found for {website}.")

    def view_password_history(self):
        """Zeigt den Verlauf der Passwörter für eine bestimmte Website an."""
        website = input("Enter the website to view password history: ")

        if website in self.passwords and "password_history" in self.passwords[website]:
            for idx, entry in enumerate(self.passwords[website]["password_history"], start=1):
                print(f"Version {idx}:")
                print(f"Username: {entry['username']}")
                print(f"Password: {self.decrypt(self.load_key(), entry['password'])}")
                print(f"Additional Info: {entry['additional_info']}")
                print(f"Created At: {entry['created_at']}")
                print(f"Changed At: {entry['changed_at']}")
                print("-" * 40)
        else:
            print(f"No password history found for {website}.")


    def delete_password(self):
        """Löscht das gespeicherte Passwort für eine bestimmte Website."""
        website = input("Enter the website you want to delete: ")
        if website in self.passwords:
            del self.passwords[website]
            self.save_passwords()
            print(f"Password for {website} has been deleted.")
        else:
            print(f"No password found for {website}.")

    def prompt_for_length(self):
        """Fordert den Benutzer auf, eine Länge für das Passwort anzugeben."""
        while True:
            try:
                length = int(input("Enter the desired password length: "))
                if length > 0:
                    return length
                else:
                    print("Please enter a positive number.")
            except ValueError:
                print("Please enter a valid number.")

    def prompt_for_option(self, prompt):
        """Fordert den Benutzer auf, eine Ja/Nein-Option anzugeben."""
        while True:
            choice = input(f"{prompt} (y/n): ").lower()
            if choice in ['y', 'n']:
                return choice == 'y'
            else:
                print("Please enter 'y' or 'n'.")

def main():
    manager = PasswordManager()

    if not manager.master_password_hash:
        print("Please set up a master password.")
        manager.set_master_password()

    while not manager.verify_master_password():
        continue

    #if not os.path.exists(manager.totp_secret_file):
    #    manager.generate_qr_code()

    #totp = pyotp.TOTP(manager.totp_secret)
    #otp = input("Enter the 2FA code from your authenticator app: ")

    #if not totp.verify(otp):
    #    print("Invalid 2FA code. Exiting.")
    #    return

    print("\n\n\033[32m" + "ACCESS GRANTED!" + "\033[0m")

    manager.load_passwords()

    while True:
        print("\nPassword Manager")
        print("0. Set Master Password")
        print("1. Add password")
        print("2. View passwords")
        print("3. Edit password")
        print("4. Delete password")
        print("5. Generate 2FA QR code")
        print("6. Generate random password")
        print("7. View password history")
        print("8. Exit")
        choice = input("\nChoose an option: ")
        print("\n")

        if choice == '0':
            manager.set_master_password()
        elif choice == '1':
            manager.add_password()
        elif choice == '2':
            manager.view_passwords()
        elif choice == '3':
            manager.edit_password()
        elif choice == '4':
            manager.delete_password()
        elif choice == '5':
            manager.generate_qr_code()
        elif choice == '6':
            manager.generate_random_password()
        elif choice == '7':
            manager.view_password_history()
        elif choice == '8':
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()




    