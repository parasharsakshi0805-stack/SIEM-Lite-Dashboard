import sys
import getpass

from database import SessionLocal
from models import User
from auth import get_password_hash


def create_or_update_user(username: str, password: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.hashed_password = get_password_hash(password)
            db.commit()
            print(f"Password updated for existing user '{username}'.")
        else:
            user = User(username=username, hashed_password=get_password_hash(password))
            db.add(user)
            db.commit()
            print(f"User '{username}' created.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python create_user.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords did not match.")
        sys.exit(1)
    if len(password) < 8:
        print("Password should be at least 8 characters.")
        sys.exit(1)

    create_or_update_user(username, password)