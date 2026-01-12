"""
Local Executor
Runs commands locally on the current system for self-analysis
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import socket
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LocalConfig:
    """Local execution configuration"""
    use_sudo: bool = True
    sudo_password: str = None
    timeout: int = 60


class LocalExecutor:
    """Executes commands locally on the current system"""

    def __init__(self, config: LocalConfig = None):
        self.config = config or LocalConfig()
        self.connected = True
        self._sudo_tested = False
        self._can_sudo = False
        self.is_windows = platform.system() == 'Windows'

    def connect(self) -> bool:
        """No connection needed for local execution"""
        self.connected = True
        if not self.is_windows and self.config.use_sudo:
            self._test_sudo()
        return True

    def _test_sudo(self) -> bool:
        """Test if we can use sudo"""
        if self._sudo_tested:
            return self._can_sudo

        self._sudo_tested = True

        # First try passwordless sudo
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self._can_sudo = True
                logger.info("Passwordless sudo available")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # If sudo password is provided, we assume it will work
        if self.config.sudo_password:
            self._can_sudo = True
            logger.info("Sudo with password configured")
            return True

        logger.warning("Sudo not available - some analysis may be limited")
        self._can_sudo = False
        return False

    def execute(self, command: str, use_sudo: bool = None, timeout: int = None) -> Tuple[int, str, str]:
        """Execute a command locally"""
        if timeout is None:
            timeout = self.config.timeout

        if use_sudo is None:
            use_sudo = self.config.use_sudo

        try:
            if self.is_windows:
                # Windows: Use PowerShell
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', command],
                    capture_output=True,
                    timeout=timeout,
                    text=True
                )
                return result.returncode, result.stdout, result.stderr

            else:
                # Linux/Unix
                if use_sudo and self._can_sudo:
                    if self.config.sudo_password:
                        # Use sudo with password via stdin
                        full_command = f"echo '{self.config.sudo_password}' | sudo -S {command}"
                        result = subprocess.run(
                            ['bash', '-c', full_command],
                            capture_output=True,
                            timeout=timeout,
                            text=True
                        )
                    else:
                        result = subprocess.run(
                            ['sudo', 'bash', '-c', command],
                            capture_output=True,
                            timeout=timeout,
                            text=True
                        )
                else:
                    result = subprocess.run(
                        ['bash', '-c', command],
                        capture_output=True,
                        timeout=timeout,
                        text=True
                    )

                return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command[:50]}...")
            return -1, "", "Command timed out"
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)

    def execute_script(self, script: str, use_sudo: bool = None, timeout: int = 120) -> Tuple[int, str, str]:
        """Execute a multi-line script locally"""
        if self.is_windows:
            return self.execute(script, use_sudo=False, timeout=timeout)
        else:
            # For Linux, escape the script properly
            script_content = script.replace("'", "'\"'\"'")
            command = f"bash -c '{script_content}'"
            return self.execute(command, use_sudo=use_sudo, timeout=timeout)

    def read_file(self, path: str, use_sudo: bool = None) -> Optional[str]:
        """Read a file locally"""
        try:
            if self.is_windows:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            else:
                if use_sudo is None:
                    use_sudo = self.config.use_sudo

                if use_sudo and self._can_sudo:
                    exit_code, stdout, stderr = self.execute(f"cat '{path}'", use_sudo=True)
                    if exit_code == 0:
                        return stdout
                    return None
                else:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
        except (IOError, OSError) as e:
            logger.debug(f"Could not read {path}: {e}")
            return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists locally"""
        return os.path.exists(path)

    def list_directory(self, path: str, use_sudo: bool = None) -> List[str]:
        """List directory contents"""
        try:
            if self.is_windows or not (use_sudo and self._can_sudo):
                return os.listdir(path)
            else:
                exit_code, stdout, _ = self.execute(f"ls -1 '{path}'", use_sudo=True)
                if exit_code == 0:
                    return [f for f in stdout.strip().split('\n') if f]
                return []
        except (IOError, OSError):
            return []

    def get_hostname(self) -> str:
        """Get the local hostname"""
        return socket.gethostname()

    def get_os_info(self) -> Dict[str, str]:
        """Get OS information from the local system"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }

        if self.is_windows:
            info['name'] = f"Windows {platform.release()}"
        else:
            # Try /etc/os-release
            content = self.read_file('/etc/os-release', use_sudo=False)
            if content:
                for line in content.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        info[key.lower()] = value.strip('"')

            # Get kernel info
            info['kernel'] = platform.release()

        return info

    def disconnect(self) -> None:
        """No disconnection needed for local execution"""
        self.connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False


class LocalWindowsExecutor(LocalExecutor):
    """Local executor optimized for Windows systems"""

    def __init__(self, config: LocalConfig = None):
        super().__init__(config)
        self.is_windows = True

    def execute(self, command: str, use_sudo: bool = None, timeout: int = None) -> Tuple[int, str, str]:
        """Execute a PowerShell command locally"""
        if timeout is None:
            timeout = self.config.timeout

        try:
            # Check if we need admin elevation (Windows equivalent of sudo)
            if use_sudo:
                # Note: Actual elevation would require UAC prompt
                # For non-interactive use, the process must already be elevated
                pass

            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command],
                capture_output=True,
                timeout=timeout,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell command timed out")
            return -1, "", "Command timed out"
        except Exception as e:
            logger.error(f"PowerShell execution failed: {e}")
            return -1, "", str(e)


class LocalLinuxExecutor(LocalExecutor):
    """Local executor optimized for Linux systems"""

    def __init__(self, config: LocalConfig = None):
        super().__init__(config)
        self.is_windows = False
