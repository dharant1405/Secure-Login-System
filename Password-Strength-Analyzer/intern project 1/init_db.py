import sqlite3
import os
from config import Config

def init_db():
    db_path = Config.DB_PATH
    
    # Check if database file already exists, if so delete it to start fresh for demo
    if os.path.exists(db_path):
        print(f"[*] Found existing database at {db_path}. Deleting for clean initialization...")
        os.remove(db_path)

    print(f"[*] Initializing secure database at {db_path}...")
    
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    # Create users table with constraints
    # - UNIQUE username and email to prevent duplicate accounts.
    # - Strict NOT NULL checks.
    # - Standard structured types.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    connection.commit()
    connection.close()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    init_db()
