#!/usr/bin/env python3
import glob
from getpass import getpass
from pathlib import Path

from flask_login import UserMixin
from werkzeug.security import generate_password_hash

USERS_DIR = "./users/"
PASSWD_MIN_LEN = 6

def get_users():
    return [{"username": Path(file).stem,
            "hash": open(file).read()
            } for file in glob.glob(f"{USERS_DIR}/*.hash")]

class User(UserMixin):
    users = get_users()

    def __init__(self, id, username=None, hash=None):
        self.id = id
        self.name = username
        self.hash = hash

    @classmethod
    def get(self, user_id):
        try:
            index = int(user_id)
        except ValueError:
            return
        if index < len(self.users):
            return User(user_id, **self.users[index])

def create_user():
    Path(USERS_DIR).mkdir(exist_ok=True)
    users = [Path(file).stem for file in glob.glob(f"{USERS_DIR}/*.hash")]

    while True:
        username = input("Username: ")
        if not username.isalnum():
            print("Please use alphanumeric characters only")
            continue
        if username in users:
            if input("This user already exists. Overwrite? (Y/n): ")\
                    .casefold() in ["", "y"]:
                break
            continue
        break

    while True:
        password = getpass("Password (Won't be displayed): ")
        if len(password) < PASSWD_MIN_LEN:
            print(f"\nPassword must at least {PASSWD_MIN_LEN} characters long")
            continue
        password2 = getpass("Confirm Password: ")
        if password != password2:
            print("\nPasswords don't match. Try again")
            continue
        break

    password_hash = generate_password_hash(password)
    return [username, password_hash]

def save_user(user):
    with open(f"{USERS_DIR}/{user[0]}.hash", "w") as f:
        f.write(user[1])

def main():
    print("ADDING NEW USER")
    try:
        user = create_user()
        if user is None:
            return
        save_user(user)
    except KeyboardInterrupt:
        print("\nCancelling...")

if __name__ == "__main__":
    main()
