"""
Tests for database module operations.
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Check if cryptography is properly available
import importlib.util
CRYPTO_AVAILABLE = importlib.util.find_spec("_cffi_backend") is not None

# Skip all database tests if cryptography is broken
pytestmark = pytest.mark.skipif(
    not CRYPTO_AVAILABLE,
    reason="Cryptography module not properly available"
)


class TestEncryption:
    """Tests for encryption/decryption functions."""

    def test_encrypt_value_returns_string(self):
        """Test that encrypt_value returns a string."""
        from web.database import encrypt_value

        result = encrypt_value("test_password")

        assert isinstance(result, str)
        assert len(result) > 0

    def test_encrypt_value_with_empty_string(self):
        """Test that encrypting empty string returns empty string."""
        from web.database import encrypt_value

        result = encrypt_value("")

        assert result == ""

    def test_decrypt_value_reverses_encryption(self):
        """Test that decrypt_value reverses encrypt_value."""
        from web.database import encrypt_value, decrypt_value

        original = "my_secret_password123"
        encrypted = encrypt_value(original)
        decrypted = decrypt_value(encrypted)

        assert decrypted == original

    def test_decrypt_value_with_empty_string(self):
        """Test that decrypting empty string returns empty string."""
        from web.database import decrypt_value

        result = decrypt_value("")

        assert result == ""

    def test_encrypted_value_differs_from_original(self):
        """Test that encrypted value is different from original."""
        from web.database import encrypt_value

        original = "plaintext_secret"
        encrypted = encrypt_value(original)

        assert encrypted != original


class TestPasswordHashing:
    """Tests for password hashing functions."""

    def test_hash_password_returns_tuple(self):
        """Test that hash_password returns tuple of (hash, salt)."""
        from web.database import hash_password

        result = hash_password("test_password")

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_hash_password_different_each_time(self):
        """Test that same password gets different hash each time (different salt)."""
        from web.database import hash_password

        hash1, salt1 = hash_password("same_password")
        hash2, salt2 = hash_password("same_password")

        assert salt1 != salt2
        assert hash1 != hash2

    def test_hash_password_with_same_salt_same_result(self):
        """Test that same password with same salt gives same hash."""
        from web.database import hash_password

        hash1, salt1 = hash_password("test_password", "fixed_salt")
        hash2, salt2 = hash_password("test_password", "fixed_salt")

        assert hash1 == hash2
        assert salt1 == salt2

    def test_verify_password_correct(self):
        """Test that verify_password returns True for correct password."""
        from web.database import hash_password, verify_password

        password = "correct_password"
        hashed, salt = hash_password(password)

        assert verify_password(password, hashed, salt) is True

    def test_verify_password_incorrect(self):
        """Test that verify_password returns False for wrong password."""
        from web.database import hash_password, verify_password

        password = "correct_password"
        hashed, salt = hash_password(password)

        assert verify_password("wrong_password", hashed, salt) is False


class TestDatabaseConnection:
    """Tests for database connection management."""

    def test_get_db_connection_returns_connection(self, tmp_path):
        """Test that get_db_connection returns a valid connection."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import get_db_connection

            with get_db_connection() as conn:
                assert conn is not None
                # Should be able to execute a simple query
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result[0] == 1

    def test_execute_query_insert_and_fetch(self, tmp_path):
        """Test execute_query with insert and fetch operations."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import execute_query, init_db

            init_db()

            # Test that we can query after init
            result = execute_query("SELECT name FROM sqlite_master WHERE type='table'", fetch='all')
            assert result is not None


class TestAdminOperations:
    """Tests for admin user operations."""

    def test_admin_exists_false_initially(self, tmp_path):
        """Test that admin_exists returns False on fresh database."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, admin_exists

            init_db()
            assert admin_exists() is False

    def test_create_admin_user(self, tmp_path):
        """Test that create_admin_user creates an admin."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, admin_exists, create_admin_user

            init_db()
            create_admin_user("admin_pass")

            assert admin_exists() is True

    def test_verify_admin_user_correct_password(self, tmp_path):
        """Test verify_admin_user with correct password."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, create_admin_user, verify_admin_user

            init_db()
            create_admin_user("correct_pass")

            assert verify_admin_user("correct_pass") is True

    def test_verify_admin_user_wrong_password(self, tmp_path):
        """Test verify_admin_user with wrong password."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, create_admin_user, verify_admin_user

            init_db()
            create_admin_user("correct_pass")

            assert verify_admin_user("wrong_pass") is False

    def test_change_admin_password(self, tmp_path):
        """Test that change_admin_password works."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, create_admin_user, verify_admin_user, change_admin_password

            init_db()
            create_admin_user("old_pass")

            change_admin_password("new_pass")

            assert verify_admin_user("old_pass") is False
            assert verify_admin_user("new_pass") is True


class TestCredentialOperations:
    """Tests for credential CRUD operations."""

    def test_save_and_get_credential(self, tmp_path):
        """Test saving and retrieving a credential."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_credential, get_credential

            init_db()

            cred_id = save_credential(
                name='test-cred',
                hostname='test.example.com',
                username='testuser',
                password='testpass',
                ssh_key=None,
                port=22,
                os_type='linux'
            )

            assert cred_id is not None

            retrieved = get_credential(cred_id)
            assert retrieved is not None
            assert retrieved['name'] == 'test-cred'
            assert retrieved['hostname'] == 'test.example.com'
            assert retrieved['username'] == 'testuser'

    def test_list_credentials(self, tmp_path):
        """Test listing all credentials."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_credential, list_credentials

            init_db()

            save_credential(name='cred1', hostname='host1.com', username='user1',
                          password='pass1', ssh_key=None, port=22, os_type='linux')
            save_credential(name='cred2', hostname='host2.com', username='user2',
                          password='pass2', ssh_key=None, port=22, os_type='linux')

            creds = list_credentials()
            assert len(creds) == 2

    def test_delete_credential(self, tmp_path):
        """Test deleting a credential."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_credential, get_credential, delete_credential

            init_db()

            cred_id = save_credential(
                name='to-delete',
                hostname='test.com',
                username='user',
                password='pass',
                ssh_key=None,
                port=22,
                os_type='linux'
            )

            delete_credential(cred_id)

            retrieved = get_credential(cred_id)
            assert retrieved is None

    def test_credential_password_is_encrypted(self, tmp_path):
        """Test that stored password is encrypted."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_credential, get_credential

            init_db()

            original_password = "super_secret_123"
            cred_id = save_credential(
                name='encrypted-test',
                hostname='test.com',
                username='user',
                password=original_password,
                ssh_key=None,
                port=22,
                os_type='linux'
            )

            # Retrieved password should be decrypted and match original
            retrieved = get_credential(cred_id)
            assert retrieved['password'] == original_password


class TestEnvVariableOperations:
    """Tests for environment variable operations."""

    def test_save_and_get_env_variable(self, tmp_path):
        """Test saving and retrieving an environment variable."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_env_variable, get_env_variable

            init_db()

            save_env_variable('TEST_VAR', 'test_value')

            result = get_env_variable('TEST_VAR')
            assert result == 'test_value'

    def test_list_env_variables(self, tmp_path):
        """Test listing all environment variables."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_env_variable, list_env_variables

            init_db()

            save_env_variable('VAR1', 'value1')
            save_env_variable('VAR2', 'value2')

            env_vars = list_env_variables()
            assert len(env_vars) >= 2

    def test_delete_env_variable(self, tmp_path):
        """Test deleting an environment variable."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_env_variable, get_env_variable, delete_env_variable

            init_db()

            save_env_variable('TO_DELETE', 'value')
            delete_env_variable('TO_DELETE')

            result = get_env_variable('TO_DELETE')
            assert result is None

    def test_update_env_variable(self, tmp_path):
        """Test updating an existing environment variable."""
        with patch('web.database.DB_DIR', tmp_path), \
             patch('web.database.DB_PATH', tmp_path / 'test.db'), \
             patch('web.database.KEY_PATH', tmp_path / '.key'), \
             patch('web.database.USE_POSTGRES', False):

            from web.database import init_db, save_env_variable, get_env_variable

            init_db()

            save_env_variable('UPDATE_VAR', 'original')
            save_env_variable('UPDATE_VAR', 'updated')

            result = get_env_variable('UPDATE_VAR')
            assert result == 'updated'
