import sqlite3
import bcrypt
from config import Config

class UserModel:
    @staticmethod
    def _get_connection():
        """Helper method to establish a connection to the SQLite database."""
        conn = sqlite3.connect(Config.DB_PATH)
        # Configure connection to return rows as dictionaries for easier data handling
        conn.row_factory = sqlite3.Row
        return conn

    @classmethod
    def create_user(cls, username, email, password):
        """
        Hashes password and inserts a new user securely.
        Protects against SQL Injection using parameterized queries.
        """
        # Secure Password Hashing using Bcrypt
        # gensalt() generates a random salt. We encode the password to bytes first.
        hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Store as string (utf-8 decoded) in SQLite text column
        password_hash = hashed_bytes.decode('utf-8')

        conn = cls._get_connection()
        cursor = conn.cursor()
        success = False
        try:
            # VULNERABILITY PREVENTED: SQL Injection
            # Secure parameterized query prevents SQL injection by treating inputs as literals rather than executable SQL code.
            query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
            cursor.execute(query, (username.strip(), email.strip().lower(), password_hash))
            conn.commit()
            success = True
        except sqlite3.IntegrityError as e:
            # Integrity error raised when UNIQUE constraint is violated (e.g., username or email exists)
            print(f"[-] Integrity error: {e}")
            success = False
        finally:
            conn.close()
        return success

    @classmethod
    def get_user_by_username(cls, username):
        """
        Retrieves user by username securely using parameterized query.
        """
        conn = cls._get_connection()
        cursor = conn.cursor()
        query = "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?"
        # Execute query passing parameters as a tuple
        cursor.execute(query, (username.strip(),))
        row = cursor.fetchone()
        conn.close()
        
        # Convert row to dict if exists
        return dict(row) if row else None

    @classmethod
    def get_user_by_email(cls, email):
        """
        Retrieves user by email securely using parameterized query.
        """
        conn = cls._get_connection()
        cursor = conn.cursor()
        query = "SELECT id, username, email, password_hash, created_at FROM users WHERE email = ?"
        cursor.execute(query, (email.strip().lower(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @classmethod
    def get_user_by_id(cls, user_id):
        """
        Retrieves user by user ID securely using parameterized query.
        """
        conn = cls._get_connection()
        cursor = conn.cursor()
        query = "SELECT id, username, email, password_hash, created_at FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def verify_password(password, hashed_password):
        """
        Verifies the plain-text password against the hashed password.
        Uses bcrypt's constant-time comparison to prevent timing attacks.
        """
        if not password or not hashed_password:
            return False
        
        # Bcrypt automatically extracts the salt from the hashed password
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            print(f"[-] Password verification exception: {e}")
            return False
