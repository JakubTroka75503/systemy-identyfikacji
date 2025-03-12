import hashlib
import os
import pyotp
import base64

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, entered_password):
    entered_hash = hash_password(entered_password)
    return stored_hash == entered_hash

def load_users(filename="users.txt"):
    users = {}
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    username, hashed_password = parts
                    users[username] = {"password": hashed_password, "secret": None}
                elif len(parts) == 3:
                    username, hashed_password, secret = parts
                    users[username] = {"password": hashed_password, "secret": secret}
    return users

def save_users(users, filename="users.txt"):
    with open(filename, "w") as f:
        for username, user_data in users.items():
            if user_data["secret"]:
                f.write(f"{username}:{user_data['password']}:{user_data['secret']}\n")
            else:
                f.write(f"{username}:{user_data['password']}\n")

users = load_users()

def register():
    username = input("Username: ")
    password = input("Password: ")
    if username in users:
        print("Username already exists.")
        return
    hashed_password = hash_password(password)
    users[username] = {"password": hashed_password, "secret": None}
    save_users(users)
    print("Registration successful!")
    enable_2fa(username)

def enable_2fa(username):
    secret = base64.b32encode(os.urandom(16)).decode('utf-8')
    users[username]["secret"] = secret
    save_users(users)
    totp = pyotp.TOTP(secret)
    print(f"2FA secret: {secret}")
    print(f"QR code URL (scan with Google Authenticator or similar): {totp.provisioning_uri(name=username)}") # usunięto issuer
    print("Please scan the QR code with your authenticator app.")

def verify_2fa(username):
    secret = users[username]["secret"]
    if not secret:
        return True
    totp = pyotp.TOTP(secret)
    otp = input("Enter 2FA code: ")
    return totp.verify(otp)

def login():
    username = input("Username: ")
    password = input("Password: ")
    user_data = users.get(username)
    if user_data and verify_password(user_data["password"], password):
        if verify_2fa(username):
            print("Login successful!")
        else:
            print("2FA verification failed.")
    else:
        print("Login failed.")

choice = input("Login (L) or Register (R)? ").upper()
if choice == "R":
    register()
else:
    login()