"""
SSH Executor
Handles SSH connections to remote servers for system analysis
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Dict, List, Any, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass

logger = logging.getLogger(__name__)

PARAMIKO_AVAILABLE = False
paramiko = None

try:
    import paramiko as _paramiko
    paramiko = _paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    pass


@dataclass
class SSHConfig:
    """SSH connection configuration"""
    hostname: str
    username: str
    port: int = 22
    private_key_path: str = None
    private_key_passphrase: str = None
    password: str = None
    sudo_password: str = None
    timeout: int = 30
    use_sudo: bool = True


class SSHExecutor:
    """Executes commands on remote servers via SSH"""

    def __init__(self, config: SSHConfig):
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError(
                "paramiko library required for SSH connections.\n"
                "Install with: pip3 install paramiko"
            )
        self.config = config
        self.client = None
        self.connected = False
        self._sudo_tested = False
        self._can_sudo = False

    def connect(self) -> bool:
        """Establish SSH connection to the remote server"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': self.config.hostname,
                'port': self.config.port,
                'username': self.config.username,
                'timeout': self.config.timeout,
                'allow_agent': True,
                'look_for_keys': True,
            }

            # Try private key authentication first
            if self.config.private_key_path:
                key_path = os.path.expanduser(self.config.private_key_path)
                if os.path.exists(key_path):
                    try:
                        # Try different key types
                        private_key = self._load_private_key(key_path)
                        connect_kwargs['pkey'] = private_key
                    except Exception as e:
                        logger.warning(f"Could not load private key: {e}")

            # Fall back to password if provided
            if self.config.password:
                connect_kwargs['password'] = self.config.password

            self.client.connect(**connect_kwargs)
            self.connected = True
            logger.info(f"Connected to {self.config.hostname}")

            # Test sudo access
            if self.config.use_sudo:
                self._test_sudo()

            return True

        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {self.config.hostname}: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.config.hostname}: {e}")
            return False
        except socket.timeout:
            logger.error(f"Connection timeout to {self.config.hostname}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to {self.config.hostname}: {e}")
            return False

    def _load_private_key(self, key_path: str):
        """Load private key, trying different formats"""
        passphrase = self.config.private_key_passphrase

        # Try RSA
        try:
            return paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
        except paramiko.SSHException:
            pass

        # Try Ed25519
        try:
            return paramiko.Ed25519Key.from_private_key_file(key_path, password=passphrase)
        except paramiko.SSHException:
            pass

        # Try ECDSA
        try:
            return paramiko.ECDSAKey.from_private_key_file(key_path, password=passphrase)
        except paramiko.SSHException:
            pass

        # Try DSA (legacy)
        try:
            return paramiko.DSSKey.from_private_key_file(key_path, password=passphrase)
        except paramiko.SSHException:
            pass

        raise paramiko.SSHException(f"Could not load private key from {key_path}")

    def _test_sudo(self) -> bool:
        """Test if we can use sudo"""
        if self._sudo_tested:
            return self._can_sudo

        self._sudo_tested = True

        # First try passwordless sudo
        exit_code, stdout, stderr = self._exec_raw("sudo -n true")
        if exit_code == 0:
            self._can_sudo = True
            logger.info("Passwordless sudo available")
            return True

        # Try with password if provided
        if self.config.sudo_password:
            exit_code, stdout, stderr = self._exec_with_sudo_password("true")
            if exit_code == 0:
                self._can_sudo = True
                logger.info("Sudo with password available")
                return True

        logger.warning("Sudo not available - some analysis may be limited")
        self._can_sudo = False
        return False

    def _exec_raw(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute command without sudo"""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to remote server")

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return exit_code, stdout.read().decode('utf-8', errors='ignore'), stderr.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)

    def _exec_with_sudo_password(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute command with sudo password via stdin"""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to remote server")

        try:
            sudo_cmd = f"sudo -S {command}"
            stdin, stdout, stderr = self.client.exec_command(sudo_cmd, timeout=timeout, get_pty=True)

            # Send password
            stdin.write(f"{self.config.sudo_password}\n")
            stdin.flush()

            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')

            # Remove password prompt from output
            output_lines = output.split('\n')
            if output_lines and '[sudo]' in output_lines[0]:
                output = '\n'.join(output_lines[1:])

            return exit_code, output, error
        except Exception as e:
            logger.error(f"Sudo command execution failed: {e}")
            return -1, "", str(e)

    def execute(self, command: str, use_sudo: bool = None, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a command on the remote server"""
        if use_sudo is None:
            use_sudo = self.config.use_sudo

        if use_sudo and self._can_sudo:
            if self.config.sudo_password:
                return self._exec_with_sudo_password(command, timeout)
            else:
                return self._exec_raw(f"sudo {command}", timeout)
        else:
            return self._exec_raw(command, timeout)

    def execute_script(self, script: str, use_sudo: bool = None, timeout: int = 120) -> Tuple[int, str, str]:
        """Execute a multi-line script on the remote server"""
        # Create a temporary script file
        script_content = script.replace("'", "'\"'\"'")  # Escape single quotes
        command = f"bash -c '{script_content}'"
        return self.execute(command, use_sudo=use_sudo, timeout=timeout)

    def read_file(self, path: str, use_sudo: bool = None) -> Optional[str]:
        """Read a file from the remote server"""
        exit_code, stdout, stderr = self.execute(f"cat '{path}'", use_sudo=use_sudo)
        if exit_code == 0:
            return stdout
        logger.debug(f"Could not read {path}: {stderr}")
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote server"""
        exit_code, _, _ = self.execute(f"test -e '{path}'", use_sudo=False)
        return exit_code == 0

    def list_directory(self, path: str, use_sudo: bool = None) -> List[str]:
        """List directory contents"""
        exit_code, stdout, stderr = self.execute(f"ls -1 '{path}'", use_sudo=use_sudo)
        if exit_code == 0:
            return [f for f in stdout.strip().split('\n') if f]
        return []

    def get_hostname(self) -> str:
        """Get the remote server's hostname"""
        exit_code, stdout, stderr = self.execute("hostname", use_sudo=False)
        if exit_code == 0:
            return stdout.strip()
        return self.config.hostname

    def get_os_info(self) -> Dict[str, str]:
        """Get OS information from the remote server"""
        info = {}

        # Try /etc/os-release first
        content = self.read_file('/etc/os-release', use_sudo=False)
        if content:
            for line in content.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    info[key.lower()] = value.strip('"')

        # Get kernel info
        exit_code, stdout, _ = self.execute("uname -r", use_sudo=False)
        if exit_code == 0:
            info['kernel'] = stdout.strip()

        return info

    def disconnect(self) -> None:
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info(f"Disconnected from {self.config.hostname}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False


class SSHExecutorPool:
    """Manages multiple SSH connections for batch processing"""

    def __init__(self):
        self.executors: Dict[str, SSHExecutor] = {}

    def add_server(self, config: SSHConfig) -> bool:
        """Add a server to the pool and connect"""
        executor = SSHExecutor(config)
        if executor.connect():
            self.executors[config.hostname] = executor
            return True
        return False

    def get_executor(self, hostname: str) -> Optional[SSHExecutor]:
        """Get executor for a specific host"""
        return self.executors.get(hostname)

    def execute_on_all(self, command: str, use_sudo: bool = True) -> Dict[str, Tuple[int, str, str]]:
        """Execute command on all connected servers"""
        results = {}
        for hostname, executor in self.executors.items():
            results[hostname] = executor.execute(command, use_sudo=use_sudo)
        return results

    def disconnect_all(self) -> None:
        """Disconnect all servers"""
        for executor in self.executors.values():
            executor.disconnect()
        self.executors.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect_all()
        return False
