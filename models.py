# models.py
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

# Simple in-memory user database
users_db = {}

class User(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.password_hash = generate_password_hash(password)
        self.two_factor_secret = None
        self.is_two_factor_enabled = False

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
