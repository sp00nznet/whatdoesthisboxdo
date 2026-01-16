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
            'has_password': bool(row['password_encrypted']),
            'has_ssh_key': bool(row['ssh_key_encrypted']),
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
            'has_password': bool(row['password_encrypted']),
            'has_ssh_key': bool(row['ssh_key_encrypted']),
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


# =============================================================================
# Datadog Integration Tables
# =============================================================================

def init_datadog_tables():
    """Initialize Datadog-related database tables."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES and POSTGRES_AVAILABLE:
            # PostgreSQL schema for Datadog tables

            # Datadog credentials storage
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_credentials (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    api_key_encrypted TEXT NOT NULL,
                    app_key_encrypted TEXT NOT NULL,
                    site VARCHAR(255) DEFAULT 'datadoghq.com',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Novel patterns database - stores learned patterns
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_patterns (
                    id SERIAL PRIMARY KEY,
                    pattern_hash VARCHAR(64) UNIQUE NOT NULL,
                    pattern_type VARCHAR(100) NOT NULL,
                    description TEXT NOT NULL,
                    metrics_involved TEXT,
                    server_type VARCHAR(100),
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    confidence REAL DEFAULT 1.0,
                    metadata TEXT,
                    is_actionable BOOLEAN DEFAULT FALSE,
                    suggested_action TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Insights history - track insights over time
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_insights (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    insight_hash VARCHAR(64) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    description TEXT,
                    metric_name VARCHAR(255),
                    metric_value REAL,
                    threshold REAL,
                    suggested_action TEXT,
                    resolution_status VARCHAR(50) DEFAULT 'open',
                    resolution_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP
                )
            ''')

            # Analysis history - store past analyses
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_analysis_history (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    health_score INTEGER,
                    server_types TEXT,
                    critical_count INTEGER DEFAULT 0,
                    warning_count INTEGER DEFAULT 0,
                    pattern_count INTEGER DEFAULT 0,
                    analysis_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Baseline metrics - store normal behavior baselines
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_baselines (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    metric_name VARCHAR(255) NOT NULL,
                    baseline_avg REAL,
                    baseline_min REAL,
                    baseline_max REAL,
                    baseline_stddev REAL,
                    sample_count INTEGER,
                    period_start TIMESTAMP,
                    period_end TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(hostname, metric_name)
                )
            ''')

        else:
            # SQLite schema for Datadog tables

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    api_key_encrypted TEXT NOT NULL,
                    app_key_encrypted TEXT NOT NULL,
                    site TEXT DEFAULT 'datadoghq.com',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_hash TEXT UNIQUE NOT NULL,
                    pattern_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    metrics_involved TEXT,
                    server_type TEXT,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    confidence REAL DEFAULT 1.0,
                    metadata TEXT,
                    is_actionable INTEGER DEFAULT 0,
                    suggested_action TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_insights (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    insight_hash TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    metric_name TEXT,
                    metric_value REAL,
                    threshold REAL,
                    suggested_action TEXT,
                    resolution_status TEXT DEFAULT 'open',
                    resolution_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    health_score INTEGER,
                    server_types TEXT,
                    critical_count INTEGER DEFAULT 0,
                    warning_count INTEGER DEFAULT 0,
                    pattern_count INTEGER DEFAULT 0,
                    analysis_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS datadog_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    baseline_avg REAL,
                    baseline_min REAL,
                    baseline_max REAL,
                    baseline_stddev REAL,
                    sample_count INTEGER,
                    period_start TIMESTAMP,
                    period_end TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(hostname, metric_name)
                )
            ''')

        conn.commit()


# =============================================================================
# Datadog Credential Functions
# =============================================================================

def save_datadog_credential(name: str, api_key: str, app_key: str,
                            site: str = 'datadoghq.com', description: str = None) -> int:
    """Save or update Datadog API credentials."""
    api_key_enc = encrypt_value(api_key)
    app_key_enc = encrypt_value(app_key)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO datadog_credentials (name, api_key_encrypted, app_key_encrypted, site, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT(name) DO UPDATE SET
                    api_key_encrypted = EXCLUDED.api_key_encrypted,
                    app_key_encrypted = EXCLUDED.app_key_encrypted,
                    site = EXCLUDED.site,
                    description = EXCLUDED.description,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ''', (name, api_key_enc, app_key_enc, site, description))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            cursor.execute('''
                INSERT INTO datadog_credentials (name, api_key_encrypted, app_key_encrypted, site, description)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    api_key_encrypted = excluded.api_key_encrypted,
                    app_key_encrypted = excluded.app_key_encrypted,
                    site = excluded.site,
                    description = excluded.description,
                    updated_at = CURRENT_TIMESTAMP
            ''', (name, api_key_enc, app_key_enc, site, description))
            conn.commit()
            return cursor.lastrowid


def get_datadog_credential(credential_id: int = None, name: str = None) -> Optional[Dict[str, Any]]:
    """Get Datadog credentials by ID or name."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if credential_id:
                cursor.execute('SELECT * FROM datadog_credentials WHERE id = %s', (credential_id,))
            elif name:
                cursor.execute('SELECT * FROM datadog_credentials WHERE name = %s', (name,))
            else:
                return None
        else:
            cursor = conn.cursor()
            if credential_id:
                cursor.execute('SELECT * FROM datadog_credentials WHERE id = ?', (credential_id,))
            elif name:
                cursor.execute('SELECT * FROM datadog_credentials WHERE name = ?', (name,))
            else:
                return None

        row = cursor.fetchone()

    if not row:
        return None

    if USE_POSTGRES:
        return {
            'id': row['id'],
            'name': row['name'],
            'api_key': decrypt_value(row['api_key_encrypted']),
            'app_key': decrypt_value(row['app_key_encrypted']),
            'site': row['site'],
            'description': row['description'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }
    else:
        return {
            'id': row['id'],
            'name': row['name'],
            'api_key': decrypt_value(row['api_key_encrypted']),
            'app_key': decrypt_value(row['app_key_encrypted']),
            'site': row['site'],
            'description': row['description'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }


def list_datadog_credentials(include_secrets: bool = False) -> List[Dict[str, Any]]:
    """List all Datadog credentials."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()

        cursor.execute('SELECT * FROM datadog_credentials ORDER BY name')
        rows = cursor.fetchall()

    credentials = []
    for row in rows:
        if USE_POSTGRES:
            cred = dict(row)
        else:
            cred = {
                'id': row['id'],
                'name': row['name'],
                'api_key_encrypted': row['api_key_encrypted'],
                'app_key_encrypted': row['app_key_encrypted'],
                'site': row['site'],
                'description': row['description'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }

        result = {
            'id': cred['id'],
            'name': cred['name'],
            'site': cred['site'],
            'description': cred['description'],
            'created_at': cred['created_at'],
            'updated_at': cred['updated_at']
        }
        if include_secrets:
            result['api_key'] = decrypt_value(cred.get('api_key_encrypted', ''))
            result['app_key'] = decrypt_value(cred.get('app_key_encrypted', ''))

        credentials.append(result)

    return credentials


def delete_datadog_credential(credential_id: int) -> bool:
    """Delete Datadog credentials."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('DELETE FROM datadog_credentials WHERE id = %s', (credential_id,))
        else:
            cursor.execute('DELETE FROM datadog_credentials WHERE id = ?', (credential_id,))
        conn.commit()
        return cursor.rowcount > 0


# =============================================================================
# Datadog Pattern Functions
# =============================================================================

def save_pattern(pattern_hash: str, pattern_type: str, description: str,
                 metrics_involved: List[str] = None, server_type: str = None,
                 confidence: float = 1.0, metadata: Dict = None,
                 is_actionable: bool = False, suggested_action: str = None) -> int:
    """Save or update a learned pattern."""
    import json

    metrics_str = json.dumps(metrics_involved) if metrics_involved else None
    metadata_str = json.dumps(metadata) if metadata else None

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO datadog_patterns
                    (pattern_hash, pattern_type, description, metrics_involved, server_type,
                     confidence, metadata, is_actionable, suggested_action)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(pattern_hash) DO UPDATE SET
                    occurrence_count = datadog_patterns.occurrence_count + 1,
                    last_seen = CURRENT_TIMESTAMP,
                    confidence = EXCLUDED.confidence
                RETURNING id
            ''', (pattern_hash, pattern_type, description, metrics_str, server_type,
                  confidence, metadata_str, is_actionable, suggested_action))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            # Check if pattern exists
            cursor.execute('SELECT id, occurrence_count FROM datadog_patterns WHERE pattern_hash = ?', (pattern_hash,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute('''
                    UPDATE datadog_patterns SET
                        occurrence_count = occurrence_count + 1,
                        last_seen = CURRENT_TIMESTAMP,
                        confidence = ?
                    WHERE pattern_hash = ?
                ''', (confidence, pattern_hash))
                conn.commit()
                return existing['id']
            else:
                cursor.execute('''
                    INSERT INTO datadog_patterns
                        (pattern_hash, pattern_type, description, metrics_involved, server_type,
                         confidence, metadata, is_actionable, suggested_action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (pattern_hash, pattern_type, description, metrics_str, server_type,
                      confidence, metadata_str, 1 if is_actionable else 0, suggested_action))
                conn.commit()
                return cursor.lastrowid


def get_patterns(pattern_type: str = None, server_type: str = None,
                 min_occurrences: int = 1, limit: int = 100) -> List[Dict[str, Any]]:
    """Get learned patterns with optional filtering."""
    import json

    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            query = 'SELECT * FROM datadog_patterns WHERE occurrence_count >= %s'
            params = [min_occurrences]
            if pattern_type:
                query += ' AND pattern_type = %s'
                params.append(pattern_type)
            if server_type:
                query += ' AND server_type = %s'
                params.append(server_type)
            query += ' ORDER BY occurrence_count DESC LIMIT %s'
            params.append(limit)
            cursor.execute(query, params)
        else:
            cursor = conn.cursor()
            query = 'SELECT * FROM datadog_patterns WHERE occurrence_count >= ?'
            params = [min_occurrences]
            if pattern_type:
                query += ' AND pattern_type = ?'
                params.append(pattern_type)
            if server_type:
                query += ' AND server_type = ?'
                params.append(server_type)
            query += ' ORDER BY occurrence_count DESC LIMIT ?'
            params.append(limit)
            cursor.execute(query, params)

        rows = cursor.fetchall()

    patterns = []
    for row in rows:
        if USE_POSTGRES:
            pattern = dict(row)
        else:
            pattern = {
                'id': row['id'],
                'pattern_hash': row['pattern_hash'],
                'pattern_type': row['pattern_type'],
                'description': row['description'],
                'metrics_involved': row['metrics_involved'],
                'server_type': row['server_type'],
                'occurrence_count': row['occurrence_count'],
                'first_seen': row['first_seen'],
                'last_seen': row['last_seen'],
                'confidence': row['confidence'],
                'metadata': row['metadata'],
                'is_actionable': bool(row['is_actionable']),
                'suggested_action': row['suggested_action']
            }

        # Parse JSON fields
        if pattern.get('metrics_involved'):
            try:
                pattern['metrics_involved'] = json.loads(pattern['metrics_involved'])
            except:
                pass
        if pattern.get('metadata'):
            try:
                pattern['metadata'] = json.loads(pattern['metadata'])
            except:
                pass

        patterns.append(pattern)

    return patterns


def is_novel_pattern(pattern_hash: str) -> bool:
    """Check if a pattern is novel (not seen before)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('SELECT id FROM datadog_patterns WHERE pattern_hash = %s', (pattern_hash,))
        else:
            cursor.execute('SELECT id FROM datadog_patterns WHERE pattern_hash = ?', (pattern_hash,))
        return cursor.fetchone() is None


# =============================================================================
# Datadog Insight Functions
# =============================================================================

def save_insight(hostname: str, insight_hash: str, category: str, severity: str,
                 title: str, description: str = None, metric_name: str = None,
                 metric_value: float = None, threshold: float = None,
                 suggested_action: str = None) -> int:
    """Save an insight to the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO datadog_insights
                    (hostname, insight_hash, category, severity, title, description,
                     metric_name, metric_value, threshold, suggested_action)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (hostname, insight_hash, category, severity, title, description,
                  metric_name, metric_value, threshold, suggested_action))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            cursor.execute('''
                INSERT INTO datadog_insights
                    (hostname, insight_hash, category, severity, title, description,
                     metric_name, metric_value, threshold, suggested_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (hostname, insight_hash, category, severity, title, description,
                  metric_name, metric_value, threshold, suggested_action))
            conn.commit()
            return cursor.lastrowid


def get_insights(hostname: str = None, severity: str = None,
                 status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Get insights with optional filtering."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            query = 'SELECT * FROM datadog_insights WHERE 1=1'
            params = []
            if hostname:
                query += ' AND hostname = %s'
                params.append(hostname)
            if severity:
                query += ' AND severity = %s'
                params.append(severity)
            if status:
                query += ' AND resolution_status = %s'
                params.append(status)
            query += ' ORDER BY created_at DESC LIMIT %s'
            params.append(limit)
            cursor.execute(query, params)
        else:
            cursor = conn.cursor()
            query = 'SELECT * FROM datadog_insights WHERE 1=1'
            params = []
            if hostname:
                query += ' AND hostname = ?'
                params.append(hostname)
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            if status:
                query += ' AND resolution_status = ?'
                params.append(status)
            query += ' ORDER BY created_at DESC LIMIT ?'
            params.append(limit)
            cursor.execute(query, params)

        rows = cursor.fetchall()

    insights = []
    for row in rows:
        if USE_POSTGRES:
            insights.append(dict(row))
        else:
            insights.append({
                'id': row['id'],
                'hostname': row['hostname'],
                'insight_hash': row['insight_hash'],
                'category': row['category'],
                'severity': row['severity'],
                'title': row['title'],
                'description': row['description'],
                'metric_name': row['metric_name'],
                'metric_value': row['metric_value'],
                'threshold': row['threshold'],
                'suggested_action': row['suggested_action'],
                'resolution_status': row['resolution_status'],
                'resolution_notes': row['resolution_notes'],
                'created_at': row['created_at'],
                'resolved_at': row['resolved_at']
            })

    return insights


def resolve_insight(insight_id: int, resolution_notes: str = None) -> bool:
    """Mark an insight as resolved."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if USE_POSTGRES:
            cursor.execute('''
                UPDATE datadog_insights
                SET resolution_status = 'resolved', resolution_notes = %s, resolved_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (resolution_notes, insight_id))
        else:
            cursor.execute('''
                UPDATE datadog_insights
                SET resolution_status = 'resolved', resolution_notes = ?, resolved_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (resolution_notes, insight_id))
        conn.commit()
        return cursor.rowcount > 0


# =============================================================================
# Datadog Analysis History Functions
# =============================================================================

def save_analysis_history(hostname: str, health_score: int, server_types: List[str],
                          critical_count: int, warning_count: int, pattern_count: int,
                          analysis_data: Dict = None) -> int:
    """Save analysis results to history."""
    import json

    server_types_str = json.dumps(server_types) if server_types else None
    analysis_data_str = json.dumps(analysis_data) if analysis_data else None

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO datadog_analysis_history
                    (hostname, health_score, server_types, critical_count, warning_count,
                     pattern_count, analysis_data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (hostname, health_score, server_types_str, critical_count, warning_count,
                  pattern_count, analysis_data_str))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            cursor.execute('''
                INSERT INTO datadog_analysis_history
                    (hostname, health_score, server_types, critical_count, warning_count,
                     pattern_count, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (hostname, health_score, server_types_str, critical_count, warning_count,
                  pattern_count, analysis_data_str))
            conn.commit()
            return cursor.lastrowid


def get_analysis_history(hostname: str = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Get analysis history for a host or all hosts."""
    import json

    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if hostname:
                cursor.execute('''
                    SELECT * FROM datadog_analysis_history
                    WHERE hostname = %s ORDER BY created_at DESC LIMIT %s
                ''', (hostname, limit))
            else:
                cursor.execute('''
                    SELECT * FROM datadog_analysis_history
                    ORDER BY created_at DESC LIMIT %s
                ''', (limit,))
        else:
            cursor = conn.cursor()
            if hostname:
                cursor.execute('''
                    SELECT * FROM datadog_analysis_history
                    WHERE hostname = ? ORDER BY created_at DESC LIMIT ?
                ''', (hostname, limit))
            else:
                cursor.execute('''
                    SELECT * FROM datadog_analysis_history
                    ORDER BY created_at DESC LIMIT ?
                ''', (limit,))

        rows = cursor.fetchall()

    history = []
    for row in rows:
        if USE_POSTGRES:
            entry = dict(row)
        else:
            entry = {
                'id': row['id'],
                'hostname': row['hostname'],
                'health_score': row['health_score'],
                'server_types': row['server_types'],
                'critical_count': row['critical_count'],
                'warning_count': row['warning_count'],
                'pattern_count': row['pattern_count'],
                'analysis_data': row['analysis_data'],
                'created_at': row['created_at']
            }

        # Parse JSON fields
        if entry.get('server_types'):
            try:
                entry['server_types'] = json.loads(entry['server_types'])
            except:
                pass
        if entry.get('analysis_data'):
            try:
                entry['analysis_data'] = json.loads(entry['analysis_data'])
            except:
                pass

        history.append(entry)

    return history


# =============================================================================
# Datadog Baseline Functions
# =============================================================================

def save_baseline(hostname: str, metric_name: str, baseline_avg: float,
                  baseline_min: float, baseline_max: float, baseline_stddev: float,
                  sample_count: int, period_start: datetime = None,
                  period_end: datetime = None) -> int:
    """Save or update a metric baseline."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if USE_POSTGRES:
            cursor.execute('''
                INSERT INTO datadog_baselines
                    (hostname, metric_name, baseline_avg, baseline_min, baseline_max,
                     baseline_stddev, sample_count, period_start, period_end)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(hostname, metric_name) DO UPDATE SET
                    baseline_avg = EXCLUDED.baseline_avg,
                    baseline_min = EXCLUDED.baseline_min,
                    baseline_max = EXCLUDED.baseline_max,
                    baseline_stddev = EXCLUDED.baseline_stddev,
                    sample_count = EXCLUDED.sample_count,
                    period_start = EXCLUDED.period_start,
                    period_end = EXCLUDED.period_end,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ''', (hostname, metric_name, baseline_avg, baseline_min, baseline_max,
                  baseline_stddev, sample_count, period_start, period_end))
            result = cursor.fetchone()
            conn.commit()
            return result[0] if result else 0
        else:
            # Check if exists
            cursor.execute('''
                SELECT id FROM datadog_baselines WHERE hostname = ? AND metric_name = ?
            ''', (hostname, metric_name))
            existing = cursor.fetchone()

            if existing:
                cursor.execute('''
                    UPDATE datadog_baselines SET
                        baseline_avg = ?, baseline_min = ?, baseline_max = ?,
                        baseline_stddev = ?, sample_count = ?, period_start = ?,
                        period_end = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE hostname = ? AND metric_name = ?
                ''', (baseline_avg, baseline_min, baseline_max, baseline_stddev,
                      sample_count, period_start, period_end, hostname, metric_name))
                conn.commit()
                return existing['id']
            else:
                cursor.execute('''
                    INSERT INTO datadog_baselines
                        (hostname, metric_name, baseline_avg, baseline_min, baseline_max,
                         baseline_stddev, sample_count, period_start, period_end)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (hostname, metric_name, baseline_avg, baseline_min, baseline_max,
                      baseline_stddev, sample_count, period_start, period_end))
                conn.commit()
                return cursor.lastrowid


def get_baselines(hostname: str) -> Dict[str, Dict[str, Any]]:
    """Get all baselines for a host as a dictionary keyed by metric name."""
    with get_db_connection() as conn:
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM datadog_baselines WHERE hostname = %s', (hostname,))
        else:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM datadog_baselines WHERE hostname = ?', (hostname,))

        rows = cursor.fetchall()

    baselines = {}
    for row in rows:
        if USE_POSTGRES:
            baseline = dict(row)
        else:
            baseline = {
                'id': row['id'],
                'hostname': row['hostname'],
                'metric_name': row['metric_name'],
                'baseline_avg': row['baseline_avg'],
                'baseline_min': row['baseline_min'],
                'baseline_max': row['baseline_max'],
                'baseline_stddev': row['baseline_stddev'],
                'sample_count': row['sample_count'],
                'period_start': row['period_start'],
                'period_end': row['period_end'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }
        baselines[baseline['metric_name']] = baseline

    return baselines


# Initialize database on import
try:
    init_db()
    init_datadog_tables()
except Exception:
    pass  # Database might not be available yet (e.g., during Docker build)
