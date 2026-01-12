"""
WinRM Executor
Handles WinRM connections to remote Windows servers for system analysis
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Any, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass

logger = logging.getLogger(__name__)

WINRM_AVAILABLE = False
winrm = None

try:
    import winrm as _winrm
    winrm = _winrm
    WINRM_AVAILABLE = True
except ImportError:
    pass


@dataclass
class WinRMConfig:
    """WinRM connection configuration"""
    hostname: str
    username: str
    password: str
    port: int = 5985
    use_ssl: bool = False
    transport: str = 'ntlm'  # ntlm, kerberos, basic
    timeout: int = 30


class WinRMExecutor:
    """Executes PowerShell commands on remote Windows servers via WinRM"""

    def __init__(self, config: WinRMConfig):
        if not WINRM_AVAILABLE:
            raise RuntimeError(
                "pywinrm library required for WinRM connections.\n"
                "Install with: pip3 install pywinrm"
            )
        self.config = config
        self.session = None
        self.connected = False

    def connect(self) -> bool:
        """Establish WinRM connection to the remote Windows server"""
        try:
            protocol = 'https' if self.config.use_ssl else 'http'
            endpoint = f"{protocol}://{self.config.hostname}:{self.config.port}/wsman"

            # Build session kwargs
            session_kwargs = {
                'auth': (self.config.username, self.config.password),
                'transport': self.config.transport,
                'operation_timeout_sec': self.config.timeout,
                'read_timeout_sec': self.config.timeout + 10
            }

            # Only set cert validation for HTTPS
            if self.config.use_ssl:
                session_kwargs['server_cert_validation'] = 'ignore'

            self.session = winrm.Session(endpoint, **session_kwargs)

            # Test connection with a simple command
            result = self.session.run_ps('$env:COMPUTERNAME')
            if result.status_code == 0:
                self.connected = True
                logger.info(f"Connected to {self.config.hostname} via WinRM")
                return True
            else:
                stderr = result.std_err
                if isinstance(stderr, bytes):
                    stderr = stderr.decode('utf-8', errors='ignore')
                logger.error(f"WinRM connection test failed: {stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to connect to {self.config.hostname} via WinRM: {e}")
            return False

    def execute(self, command: str, use_powershell: bool = True, timeout: int = None) -> Tuple[int, str, str]:
        """Execute a command on the remote Windows server"""
        if not self.connected or not self.session:
            raise RuntimeError("Not connected to remote Windows server")

        try:
            if use_powershell:
                # Try run_ps first
                try:
                    result = self.session.run_ps(command)
                except TypeError as te:
                    # Fallback: encode command as base64 and run via cmd
                    if 'startswith' in str(te):
                        import base64
                        encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
                        ps_cmd = f'powershell -EncodedCommand {encoded}'
                        result = self.session.run_cmd(ps_cmd)
                    else:
                        raise
            else:
                result = self.session.run_cmd(command)

            # Handle both bytes and string responses
            stdout = result.std_out
            stderr = result.std_err

            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='ignore')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='ignore')

            return result.status_code, stdout, stderr

        except TypeError as e:
            # Handle startswith bytes/str mismatch error from pywinrm
            if 'startswith' in str(e):
                logger.warning(f"pywinrm encoding issue, retrying with encoded command")
                try:
                    import base64
                    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
                    ps_cmd = f'powershell -EncodedCommand {encoded}'
                    result = self.session.run_cmd(ps_cmd)

                    stdout = result.std_out
                    stderr = result.std_err
                    if isinstance(stdout, bytes):
                        stdout = stdout.decode('utf-8', errors='ignore')
                    if isinstance(stderr, bytes):
                        stderr = stderr.decode('utf-8', errors='ignore')
                    return result.status_code, stdout, stderr
                except Exception as retry_error:
                    logger.error(f"Retry also failed: {retry_error}")
                    return -1, "", str(e)
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)

    def execute_script(self, script: str, timeout: int = 120) -> Tuple[int, str, str]:
        """Execute a multi-line PowerShell script on the remote server"""
        return self.execute(script, use_powershell=True, timeout=timeout)

    def read_file(self, path: str) -> Optional[str]:
        """Read a file from the remote Windows server"""
        # Escape path for PowerShell
        escaped_path = path.replace("'", "''")
        exit_code, stdout, stderr = self.execute(f"Get-Content -Path '{escaped_path}' -Raw -ErrorAction SilentlyContinue")
        if exit_code == 0:
            return stdout
        logger.debug(f"Could not read {path}: {stderr}")
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote Windows server"""
        escaped_path = path.replace("'", "''")
        exit_code, stdout, _ = self.execute(f"Test-Path -Path '{escaped_path}'")
        return exit_code == 0 and 'True' in stdout

    def list_directory(self, path: str) -> List[str]:
        """List directory contents"""
        escaped_path = path.replace("'", "''")
        exit_code, stdout, _ = self.execute(f"Get-ChildItem -Path '{escaped_path}' -Name -ErrorAction SilentlyContinue")
        if exit_code == 0:
            return [f.strip() for f in stdout.strip().split('\n') if f.strip()]
        return []

    def get_hostname(self) -> str:
        """Get the remote server's hostname"""
        exit_code, stdout, _ = self.execute("$env:COMPUTERNAME")
        if exit_code == 0:
            return stdout.strip()
        return self.config.hostname

    def get_os_info(self) -> Dict[str, str]:
        """Get OS information from the remote Windows server"""
        info = {}

        # Get Windows version info
        script = """
$os = Get-WmiObject Win32_OperatingSystem
@{
    'name' = $os.Caption
    'version' = $os.Version
    'build' = $os.BuildNumber
    'architecture' = $os.OSArchitecture
    'install_date' = $os.InstallDate
    'last_boot' = $os.LastBootUpTime
    'registered_user' = $os.RegisteredUser
} | ConvertTo-Json
"""
        exit_code, stdout, _ = self.execute(script)
        if exit_code == 0:
            try:
                import json
                info = json.loads(stdout)
            except:
                pass

        return info

    def disconnect(self) -> None:
        """Close the WinRM connection"""
        self.session = None
        self.connected = False
        logger.info(f"Disconnected from {self.config.hostname}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False


class WinRMExecutorPool:
    """Manages multiple WinRM connections for batch processing"""

    def __init__(self):
        self.executors: Dict[str, WinRMExecutor] = {}

    def add_server(self, config: WinRMConfig) -> bool:
        """Add a server to the pool and connect"""
        executor = WinRMExecutor(config)
        if executor.connect():
            self.executors[config.hostname] = executor
            return True
        return False

    def get_executor(self, hostname: str) -> Optional[WinRMExecutor]:
        """Get executor for a specific host"""
        return self.executors.get(hostname)

    def execute_on_all(self, command: str) -> Dict[str, Tuple[int, str, str]]:
        """Execute command on all connected servers"""
        results = {}
        for hostname, executor in self.executors.items():
            results[hostname] = executor.execute(command)
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
