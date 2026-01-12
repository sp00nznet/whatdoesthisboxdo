"""
Database module for secure credential and configuration storage.
Supports SQLite (local) and PostgreSQL (Docker/production).
Uses Fernet encryption for sensitive data.
"""

import os
import base64
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

# Try to import cryptography for encryption
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

# Try to import psycopg2 for PostgreSQL
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    psycopg2 = None

import sqlite3

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', '')
USE_POSTGRES = DATABASE_URL.startswith('postgres')

# SQLite paths (fallback)
DB_DIR = Path(__file__).parent / 'data'
DB_PATH = DB_DIR / 'whatdoesthisboxdo.db'
KEY_PATH = DB_DIR / '.encryption_key'


def get_encryption_key() -> bytes:
    """Get or generate the encryption key."""
    # Try environment variable first (required for Docker)
    env_key = os.environ.get('ENCRYPTION_KEY')
    if env_key:
        # Ensure it's valid Fernet key length
        if len(env_key) == 44:  # Base64-encoded 32 bytes
            return env_key.encode()
        # Generate proper key from provided secret
        return base64.urlsafe_b64encode(hashlib.sha256(env_key.encode()).digest())

    # For local SQLite, use key file
    DB_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()

    # Generate new key
    if CRYPTO_AVAILABLE:
        key = Fernet.generate_key()
    else:
        key = base64.urlsafe_b64encode(secrets.token_bytes(32))

    KEY_PATH.write_bytes(key)
    KEY_PATH.chmod(0o600)
    return key


def encrypt_value(value: str) -> str:
    """Encrypt a string value."""
    if not value:
        return ''
    if not CRYPTO_AVAILABLE:
        return 'b64:' + base64.b64encode(value.encode()).decode()

    key = get_encryption_key()
    f = Fernet(key)
    return 'enc:' + f.encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    """Decrypt an encrypted string value."""
    if not encrypted:
        return ''

    if encrypted.startswith('b64:'):
        return base64.b64decode(encrypted[4:]).decode()

    if encrypted.startswith('enc:'):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required to decrypt")
        key = get_encryption_key()
        f = Fernet(key)
        return f.decrypt(encrypted[4:].encode()).decode()

    return encrypted


def hash_password(password: str, salt: str = None) -> tuple:
    """Hash a password with salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.b64encode(hashed).decode(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify a password against its hash."""
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(new_hash, hashed)


# =============================================================================
# Database Connection Management
# =============================================================================

@contextmanager
def get_db_connection():
    """Get a database connection (PostgreSQL or SQLite)."""
    conn = None
    try:
        if USE_POSTGRES and POSTGRES_AVAILABLE:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = False
        else:
            DB_DIR.mkdir(exist_ok=True)
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()


def execute_query(query: str, params: tuple = None, fetch: str = None):
    """Execute a query with proper parameter handling for both databases."""
    with get_db_connection() as conn:
        if USE_POSTGRES and POSTGRES_AVAILABLE:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Convert ? placeholders to %s for PostgreSQL
            query = query.replace('?', '%s')
        else:
            cursor = conn.cursor()

        cursor.execute(query, params or ())

        result = None
        if fetch == 'one':
            row = cursor.fetchone()
            result = dict(row) if row else None
        elif fetch == 'all':
            rows = cursor.fetchall()
            result = [dict(row) for row in rows]
        elif fetch == 'lastrowid':
            if USE_POSTGRES:
                result = cursor.fetchone()['id'] if cursor.description else None
            else:
                result = cursor.lastrowid
        elif fetch == 'rowcount':
            result = cursor.rowcount

        conn.commit()
        return result


def init_db():
    """Initialize the database schema."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES and POSTGRES_AVAILABLE:
            # PostgreSQL schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    password_salt VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    hostname VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    password_encrypted TEXT,
                    ssh_key_encrypted TEXT,
                    port INTEGER DEFAULT 22,
                    os_type VARCHAR(50) DEFAULT 'linux',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS env_variables (
                    id SERIAL PRIMARY KEY,
                    key VARCHAR(255) UNIQUE NOT NULL,
                    value_encrypted TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        else:
            # SQLite schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_encrypted TEXT,
                    ssh_key_encrypted TEXT,
                    port INTEGER DEFAULT 22,
                    os_type TEXT DEFAULT 'linux',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS env_variables (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value_encrypted TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

        conn.commit()


# =============================================================================
# Admin User Functions
# =============================================================================

def create_admin_user(username: str, password: str) -> bool:
    """Create a new admin user."""
    password_hash, salt = hash_password(password)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if USE_POSTGRES:
                cursor.execute(
                    'INSERT INTO admin_users (username, password_hash, password_salt) VALUES (%s, %s, %s)',
                    (username, password_hash, salt)
                )
            else:
                cursor.execute(
                    'INSERT INTO admin_users (username, password_hash, password_salt) VALUES (?, ?, ?)',
                    (username, password_hash, salt)
                )
            conn.commit()
            return True
    except Exception:
        return False


def verify_admin_user(username: str, password: str) -> bool:
    """Verify admin user credentials."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT password_hash, password_salt FROM admin_users WHERE username = %s', (username,))
        else:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, password_salt FROM admin_users WHERE username = ?', (username,))

        row = cursor.fetchone()

    if not row:
        return False

    if USE_POSTGRES:
        return verify_password(password, row['password_hash'], row['password_salt'])
    else:
        return verify_password(password, row['password_hash'], row['password_salt'])


def update_admin_login(username: str):
    """Update last login timestamp."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('UPDATE admin_users SET last_login = %s WHERE username = %s', (datetime.now(), username))
        else:
            cursor.execute('UPDATE admin_users SET last_login = ? WHERE username = ?', (datetime.now(), username))
        conn.commit()


def admin_exists() -> bool:
    """Check if any admin user exists."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM admin_users')
        row = cursor.fetchone()
        return row[0] > 0 if row else False


def change_admin_password(username: str, new_password: str) -> bool:
    """Change admin password."""
    password_hash, salt = hash_password(new_password)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute(
                'UPDATE admin_users SET password_hash = %s, password_salt = %s WHERE username = %s',
                (password_hash, salt, username)
            )
        else:
            cursor.execute(
                'UPDATE admin_users SET password_hash = ?, password_salt = ? WHERE username = ?',
                (password_hash, salt, username)
            )
        conn.commit()
        return cursor.rowcount > 0


# =============================================================================
# Credential Functions
# =============================================================================

def save_credential(name: str, hostname: str, username: str,
                   password: str = None, ssh_key: str = None,
                   port: int = 22, os_type: str = 'linux',
                   description: str = None) -> int:
    """Save or update a server credential."""
    password_enc = encrypt_value(password) if password else None
    ssh_key_enc = encrypt_value(ssh_key) if ssh_key else None

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO credentials (name, hostname, username, password_encrypted,
                                        ssh_key_encrypted, port, os_type, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(name) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    username = EXCLUDED.username,
                    password_encrypted = EXCLUDED.password_encrypted,
                    ssh_key_encrypted = EXCLUDED.ssh_key_encrypted,
                    port = EXCLUDED.port,
                    os_type = EXCLUDED.os_type,
                    description = EXCLUDED.description,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ''', (name, hostname, username, password_enc, ssh_key_enc, port, os_type, description))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            cursor.execute('''
                INSERT INTO credentials (name, hostname, username, password_encrypted,
                                        ssh_key_encrypted, port, os_type, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    hostname = excluded.hostname,
                    username = excluded.username,
                    password_encrypted = excluded.password_encrypted,
                    ssh_key_encrypted = excluded.ssh_key_encrypted,
                    port = excluded.port,
                    os_type = excluded.os_type,
                    description = excluded.description,
                    updated_at = CURRENT_TIMESTAMP
            ''', (name, hostname, username, password_enc, ssh_key_enc, port, os_type, description))
            conn.commit()
            return cursor.lastrowid


def get_credential(credential_id: int = None, name: str = None) -> Optional[Dict[str, Any]]:
    """Get a credential by ID or name."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if credential_id:
                cursor.execute('SELECT * FROM credentials WHERE id = %s', (credential_id,))
            elif name:
                cursor.execute('SELECT * FROM credentials WHERE name = %s', (name,))
            else:
                return None
        else:
            cursor = conn.cursor()
            if credential_id:
                cursor.execute('SELECT * FROM credentials WHERE id = ?', (credential_id,))
            elif name:
                cursor.execute('SELECT * FROM credentials WHERE name = ?', (name,))
            else:
                return None

        row = cursor.fetchone()

    if not row:
        return None

    if USE_POSTGRES:
        return {
            'id': row['id'],
            'name': row['name'],
            'hostname': row['hostname'],
            'username': row['username'],
            'password': decrypt_value(row['password_encrypted']) if row['password_encrypted'] else None,
            'ssh_key': decrypt_value(row['ssh_key_encrypted']) if row['ssh_key_encrypted'] else None,
            'port': row['port'],
            'os_type': row['os_type'],
            'description': row['description'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }
    else:
        return {
            'id': row['id'],
            'name': row['name'],
            'hostname': row['hostname'],
            'username': row['username'],
            'password': decrypt_value(row['password_encrypted']) if row['password_encrypted'] else None,
            'ssh_key': decrypt_value(row['ssh_key_encrypted']) if row['ssh_key_encrypted'] else None,
            'port': row['port'],
            'os_type': row['os_type'],
            'description': row['description'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }


def list_credentials(include_secrets: bool = False) -> List[Dict[str, Any]]:
    """List all credentials."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()

        cursor.execute('SELECT * FROM credentials ORDER BY name')
        rows = cursor.fetchall()

    credentials = []
    for row in rows:
        if USE_POSTGRES:
            cred = dict(row)
        else:
            cred = {
                'id': row['id'],
                'name': row['name'],
                'hostname': row['hostname'],
                'username': row['username'],
                'port': row['port'],
                'os_type': row['os_type'],
                'description': row['description'],
                'password_encrypted': row['password_encrypted'],
                'ssh_key_encrypted': row['ssh_key_encrypted'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }

        result = {
            'id': cred['id'],
            'name': cred['name'],
            'hostname': cred['hostname'],
            'username': cred['username'],
            'port': cred['port'],
            'os_type': cred['os_type'],
            'description': cred['description'],
            'has_password': bool(cred.get('password_encrypted')),
            'has_ssh_key': bool(cred.get('ssh_key_encrypted')),
            'created_at': cred['created_at'],
            'updated_at': cred['updated_at']
        }
        if include_secrets:
            result['password'] = decrypt_value(cred.get('password_encrypted', '')) if cred.get('password_encrypted') else None
            result['ssh_key'] = decrypt_value(cred.get('ssh_key_encrypted', '')) if cred.get('ssh_key_encrypted') else None
        credentials.append(result)

    return credentials


def delete_credential(credential_id: int) -> bool:
    """Delete a credential."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('DELETE FROM credentials WHERE id = %s', (credential_id,))
        else:
            cursor.execute('DELETE FROM credentials WHERE id = ?', (credential_id,))
        conn.commit()
        return cursor.rowcount > 0


# =============================================================================
# Environment Variable Functions
# =============================================================================

def save_env_variable(key: str, value: str, description: str = None) -> int:
    """Save or update an environment variable."""
    value_enc = encrypt_value(value)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO env_variables (key, value_encrypted, description)
                VALUES (%s, %s, %s)
                ON CONFLICT(key) DO UPDATE SET
                    value_encrypted = EXCLUDED.value_encrypted,
                    description = EXCLUDED.description,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ''', (key, value_enc, description))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            cursor.execute('''
                INSERT INTO env_variables (key, value_encrypted, description)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_encrypted = excluded.value_encrypted,
                    description = excluded.description,
                    updated_at = CURRENT_TIMESTAMP
            ''', (key, value_enc, description))
            conn.commit()
            return cursor.lastrowid


def get_env_variable(key: str) -> Optional[str]:
    """Get an environment variable value."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT value_encrypted FROM env_variables WHERE key = %s', (key,))
        else:
            cursor = conn.cursor()
            cursor.execute('SELECT value_encrypted FROM env_variables WHERE key = ?', (key,))

        row = cursor.fetchone()

    if not row:
        return None

    if USE_POSTGRES:
        return decrypt_value(row['value_encrypted'])
    else:
        return decrypt_value(row['value_encrypted'])


def list_env_variables(include_values: bool = False) -> List[Dict[str, Any]]:
    """List all environment variables."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()

        cursor.execute('SELECT * FROM env_variables ORDER BY key')
        rows = cursor.fetchall()

    variables = []
    for row in rows:
        if USE_POSTGRES:
            var = dict(row)
        else:
            var = {
                'id': row['id'],
                'key': row['key'],
                'value_encrypted': row['value_encrypted'],
                'description': row['description'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }

        result = {
            'id': var['id'],
            'key': var['key'],
            'description': var['description'],
            'created_at': var['created_at'],
            'updated_at': var['updated_at']
        }
        if include_values:
            result['value'] = decrypt_value(var.get('value_encrypted', ''))
        else:
            result['value'] = '********'
        variables.append(result)

    return variables


def delete_env_variable(key: str) -> bool:
    """Delete an environment variable."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('DELETE FROM env_variables WHERE key = %s', (key,))
        else:
            cursor.execute('DELETE FROM env_variables WHERE key = ?', (key,))
        conn.commit()
        return cursor.rowcount > 0


def load_env_variables_to_environ():
    """Load all stored env variables into os.environ."""
    try:
        for var in list_env_variables(include_values=True):
            if var['key'] not in os.environ:
                os.environ[var['key']] = var['value']
    except Exception:
        # Database might not be initialized yet
        pass


# Initialize database on import
try:
    init_db()
except Exception:
    pass  # Database might not be available yet (e.g., during Docker build)
