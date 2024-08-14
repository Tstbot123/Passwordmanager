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

# Versuche das curses Modul zu importieren, falls verfügbar
try:
    import curses
except ImportError:
    curses = None  # Fallback-Option


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
                return False
            else:
                self.failed_attempts = 0
                self.lockout_time = 0

        master_password = getpass.getpass("Enter your master password: ")
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
        encrypted_data = fernet.encrypt(data.encode())
        #konvertiere die daten in einen hex codierten string
        return encrypted_data.hex() 
    def decrypt(self, key, data):
        """Entschlüsselt die Daten mit dem bereitgestellten Schlüssel."""
        fernet = Fernet(key)
        encrypted_data = bytes.fromhex (data) #konvertiere den string zrück in bytes und entschlüssle ihn
        return fernet.decrypt(encrypted_data).decode() 

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
            print("Warning: Password is too short! Consider using at least 8 characters.")
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
                print("Password has been pwned!")
            else:
                print("Password is safe.")

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
        length = self.prompt_for_integer("Enter the desired password length: ")
        use_uppercase = self.prompt_for_yes_no("Include uppercase letters (A-Z)?")
        use_lowercase = self.prompt_for_yes_no("Include lowercase letters (a-z)?")
        use_digits = self.prompt_for_yes_no("Include digits (0-9)?")
        use_special = self.prompt_for_yes_no("Include special characters (!@#$%^&*)?")
        exclude_chars = input("Enter any characters to exclude: ")

        try:
            password = self.generate_password(length, use_uppercase, use_lowercase, use_digits, use_special, exclude_chars)
            print(f"Generated password: {password}")
        except ValueError as e:
            print(e)

    def prompt_for_yes_no(self, prompt):
        """Fragt den Benutzer nach einer Ja/Nein-Antwort."""
        while True:
            response = input(prompt + " (y/n): ").lower()
            if response in ['y', 'n']:
                return response == 'y'
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

    def prompt_for_integer(self, prompt):
        """Fragt den Benutzer nach einer Ganzzahl."""
        while True:
            try:
                return int(input(prompt))
            except ValueError:
                print("Invalid input. Please enter an integer.")

    def add_password(self):
        """Fügt ein neues Passwort hinzu, nachdem es validiert wurde."""
        key = self.load_key()
        website = input("Enter the website name: ")
        username = input("Enter the username: ")
        password = getpass.getpass("Enter the password: ")

        if not self.check_password_strength(password):
            print("The provided password does not meet the security criteria.")
            return

        if self.check_password_reuse(password):
            print("The provided password is already in use.")
            return

        self.check_password_breach(password)

        self.passwords[website] = {
            "username": username,
            "password": self.encrypt(key, password),
            "created_at": datetime.now().isoformat()
        }
        self.save_passwords()
        print(f"Password for {website} added successfully.")

    def retrieve_password(self):
        """Ruft ein gespeichertes Passwort ab."""
        key = self.load_key()
        website = input("Enter the website name: ")

        if website in self.passwords:
            password = self.decrypt(key, self.passwords[website]["password"])
            print(f"Password for {website}: {password}")
        else:
            print(f"No password found for {website}.")

    def main_menu(self):
        """Zeigt das Hauptmenü und ermöglicht dem Benutzer die Navigation."""
        if curses:
            # Verwende curses für die Benutzeroberfläche
            curses.wrapper(self.curses_main_menu)
        else:
            # Fallback für Systeme ohne curses
            while True:
                print("\nPassword Manager Menu")
                print("1. Add a new password")
                print("2. Retrieve a password")
                print("3. Generate a random password")
                print("4. Set Master Password")
                print("5. Generate QR Code for 2FA")
                print("6. Exit")
                choice = input("Enter your choice: ")

                if choice == '1':
                    self.add_password()
                elif choice == '2':
                    self.retrieve_password()
                elif choice == '3':
                    self.generate_random_password()
                elif choice == '4':
                    self.set_master_password()
                elif choice == '5':
                    self.generate_qr_code()
                elif choice == '6':
                    break
                else:
                    print("Invalid choice. Please try again.")

    def curses_main_menu(self, stdscr):
        """Curses-basierte Hauptmenü-Funktion."""
        curses.curs_set(0)
        current_row = 0

    

        menu = ["Add a new password", "Retrieve a password", "Generate a random password", "Set Master Password", "Generate QR Code for 2FA", "Exit"]

        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            for idx, row in enumerate(menu):
                x = w // 2 - len(row) // 2
                y = h // 2 - len(menu) // 2 + idx
                if idx == current_row:
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(y, x, row)
                    stdscr.attroff(curses.color_pair(1))
                else:
                    stdscr.addstr(y, x, row)

            stdscr.refresh()

            key = stdscr.getch()

            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(menu) - 1:
                current_row += 1
            elif key == curses.KEY_ENTER or key in [10, 13]:
                if current_row == len(menu) - 1:
                    break  # Beenden
                elif current_row == 0:
                    self.add_password()
                elif current_row == 1:
                    self.retrieve_password()
                elif current_row == 2:
                    self.generate_random_password()
                elif current_row == 3:
                    self.set_master_password()
                elif current_row == 4:
                    self.generate_qr_code()

if __name__ == "__main__":
    manager = PasswordManager()
    if manager.master_password_hash is None:
        manager.set_master_password()
    if manager.verify_master_password():
        manager.main_menu()
