import random
import string
import requests
import hashlib
import base64
import pyotp
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    elif any(char in string.punctuation for char in password):
        return "Strong"
    else:
        return "Medium"

def have_i_been_pwned(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5_chars, tail = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5_chars}"
    response = requests.get(url)
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return int(count)
    return 0

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_totp_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data).decode()
