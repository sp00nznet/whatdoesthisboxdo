"""
Remote System Analyzer
Analyzes remote systems via SSH connection
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional

from connectors.ssh_executor import SSHExecutor

logger = logging.getLogger(__name__)


class RemoteProcessAnalyzer:
    """Analyzes processes on a remote system via SSH"""

    def __init__(self, ssh: SSHExecutor):
        self.ssh = ssh
        self.data = {
            'running': [],
            'services': [],
            'connections': [],
            'listening_ports': [],
            'resource_usage': {}
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full process analysis on remote system"""
        self._get_running_processes()
        self._get_services()
        self._get_connections()
        self._get_resource_usage()
        return self.data

    def _get_running_processes(self) -> List[Dict]:
        """Get running processes from remote system"""
        processes = []

        # Use ps command
        exit_code, stdout, _ = self.ssh.execute(
            "ps aux --no-headers",
            use_sudo=True
        )

        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': int(parts[1]) if parts[1].isdigit() else 0,
                            'cpu_percent': float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                            'memory_percent': float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            'vsz': parts[4],
                            'rss': parts[5],
                            'tty': parts[6],
                            'status': parts[7],
                            'start': parts[8],
                            'time': parts[9],
                            'name': parts[10].split()[0] if parts[10] else '',
                            'cmdline': parts[10]
                        })

        self.data['running'] = processes
        return processes

    def _get_services(self) -> List[Dict]:
        """Get systemd services from remote system"""
        services = []

        exit_code, stdout, _ = self.ssh.execute(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            use_sudo=True
        )

        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if line:
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        service_name = parts[0].replace('.service', '')
                        services.append({
                            'name': service_name,
                            'load': parts[1],
                            'active': parts[2],
                            'status': parts[3],
                            'description': parts[4] if len(parts) > 4 else ''
                        })

        self.data['services'] = services
        return services

    def _get_connections(self) -> List[Dict]:
        """Get network connections from remote system"""
        connections = []

        # Try ss first (modern systems)
        exit_code, stdout, _ = self.ssh.execute(
            "ss -tunapH 2>/dev/null || netstat -tunapn 2>/dev/null",
            use_sudo=True
        )

        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if line and not line.startswith('Netid'):
                    parts = line.split()
                    if len(parts) >= 5:
                        # Parse local address
                        local = parts[4] if len(parts) > 4 else parts[3]
                        local_parts = local.rsplit(':', 1)
                        local_addr = local_parts[0] if local_parts else ''
                        local_port = int(local_parts[1]) if len(local_parts) > 1 and local_parts[1].isdigit() else 0

                        # Parse remote address
                        remote = parts[5] if len(parts) > 5 else ''
                        remote_parts = remote.rsplit(':', 1)
                        remote_addr = remote_parts[0] if remote_parts else ''
                        remote_port = int(remote_parts[1]) if len(remote_parts) > 1 and remote_parts[1].isdigit() else 0

                        conn = {
                            'type': parts[0] if parts[0] in ['tcp', 'udp', 'tcp6', 'udp6'] else 'unknown',
                            'status': parts[1] if len(parts) > 1 else '',
                            'local_addr': local_addr.strip('[]'),
                            'local_port': local_port,
                            'remote_addr': remote_addr.strip('[]'),
                            'remote_port': remote_port,
                            'process': parts[-1] if len(parts) > 6 else 'unknown'
                        }
                        connections.append(conn)

        # Extract listening ports
        self.data['listening_ports'] = [
            {'port': c['local_port'], 'process': c['process'], 'addr': c['local_addr']}
            for c in connections if c['status'] in ['LISTEN', 'UNCONN'] and c['local_port'] > 0
        ]

        self.data['connections'] = connections
        return connections

    def _get_resource_usage(self) -> Dict:
        """Get system resource usage from remote system"""
        usage = {'cpu': {}, 'memory': {}, 'disk': {}, 'network': {}}

        # CPU info
        exit_code, stdout, _ = self.ssh.execute("nproc", use_sudo=False)
        if exit_code == 0:
            usage['cpu']['count'] = int(stdout.strip())

        exit_code, stdout, _ = self.ssh.execute("cat /proc/loadavg", use_sudo=False)
        if exit_code == 0:
            parts = stdout.strip().split()
            usage['cpu']['load_avg'] = [float(x) for x in parts[:3]]

        # Memory info
        exit_code, stdout, _ = self.ssh.execute("free -b", use_sudo=False)
        if exit_code == 0:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    usage['memory'] = {
                        'total': int(parts[1]),
                        'used': int(parts[2]),
                        'free': int(parts[3]) if len(parts) > 3 else 0,
                        'percent': round(int(parts[2]) / int(parts[1]) * 100, 1) if int(parts[1]) > 0 else 0
                    }

        # Disk usage
        exit_code, stdout, _ = self.ssh.execute("df -B1 --output=target,size,used,avail,pcent", use_sudo=False)
        if exit_code == 0:
            for line in stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    mount = parts[0]
                    if mount.startswith('/') and not mount.startswith('/snap'):
                        usage['disk'][mount] = {
                            'total': int(parts[1]) if parts[1].isdigit() else 0,
                            'used': int(parts[2]) if parts[2].isdigit() else 0,
                            'free': int(parts[3]) if parts[3].isdigit() else 0,
                            'percent': int(parts[4].rstrip('%')) if parts[4].rstrip('%').isdigit() else 0
                        }

        self.data['resource_usage'] = usage
        return usage


class RemoteFileAnalyzer:
    """Analyzes files and packages on a remote system via SSH"""

    def __init__(self, ssh: SSHExecutor):
        self.ssh = ssh
        self.data = {
            'configurations': [],
            'installed_packages': [],
            'service_configs': {},
            'important_paths': [],
            'recently_modified': []
        }

    def analyze(self, paths: List[str] = None) -> Dict[str, Any]:
        """Run full file analysis on remote system"""
        self._get_installed_packages()
        self._get_service_configs()
        self._get_important_paths()
        self._get_recently_modified()
        return self.data

    def _get_installed_packages(self) -> List[Dict]:
        """Get installed packages from remote system"""
        packages = []

        # Try dpkg (Debian/Ubuntu)
        exit_code, stdout, _ = self.ssh.execute(
            "dpkg-query -W -f='${Package}|${Version}|${Status}\\n' 2>/dev/null | grep 'install ok installed'",
            use_sudo=False
        )

        if exit_code == 0 and stdout.strip():
            for line in stdout.strip().split('\n'):
                parts = line.split('|')
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1],
                        'manager': 'apt'
                    })
        else:
            # Try rpm (RHEL/CentOS)
            exit_code, stdout, _ = self.ssh.execute(
                "rpm -qa --qf '%{NAME}|%{VERSION}\\n' 2>/dev/null",
                use_sudo=False
            )
            if exit_code == 0:
                for line in stdout.strip().split('\n'):
                    parts = line.split('|')
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'manager': 'yum'
                        })

        # Get pip packages
        exit_code, stdout, _ = self.ssh.execute(
            "pip3 list --format=freeze 2>/dev/null || pip list --format=freeze 2>/dev/null",
            use_sudo=False
        )
        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if '==' in line:
                    name, version = line.split('==', 1)
                    packages.append({
                        'name': name,
                        'version': version,
                        'manager': 'pip'
                    })

        self.data['installed_packages'] = packages
        return packages

    def _get_service_configs(self) -> Dict:
        """Get service configuration locations"""
        configs = {}

        service_paths = {
            'nginx': ['/etc/nginx'],
            'apache': ['/etc/apache2', '/etc/httpd'],
            'mysql': ['/etc/mysql'],
            'postgresql': ['/etc/postgresql'],
            'docker': ['/etc/docker'],
            'systemd': ['/etc/systemd/system'],
        }

        for service, paths in service_paths.items():
            for path in paths:
                exit_code, stdout, _ = self.ssh.execute(f"ls -la '{path}' 2>/dev/null", use_sudo=True)
                if exit_code == 0:
                    configs[service] = [{
                        'path': path,
                        'files': self._parse_ls_output(stdout)
                    }]
                    break

        self.data['service_configs'] = configs
        return configs

    def _parse_ls_output(self, output: str) -> List[Dict]:
        """Parse ls -la output"""
        files = []
        for line in output.strip().split('\n')[1:]:  # Skip total line
            parts = line.split(None, 8)
            if len(parts) >= 9:
                files.append({
                    'permissions': parts[0],
                    'owner': parts[2],
                    'group': parts[3],
                    'size': int(parts[4]) if parts[4].isdigit() else 0,
                    'name': parts[8]
                })
        return files

    def _get_important_paths(self) -> List[Dict]:
        """Get important directory information"""
        paths = []
        important_dirs = ['/etc', '/var/log', '/opt', '/home', '/var/www', '/srv']

        for dir_path in important_dirs:
            exit_code, stdout, _ = self.ssh.execute(
                f"du -sb '{dir_path}' 2>/dev/null && ls -1 '{dir_path}' 2>/dev/null | wc -l",
                use_sudo=True
            )
            if exit_code == 0:
                lines = stdout.strip().split('\n')
                if lines:
                    size_parts = lines[0].split()
                    paths.append({
                        'path': dir_path,
                        'size': int(size_parts[0]) if size_parts[0].isdigit() else 0,
                        'contents_count': int(lines[1]) if len(lines) > 1 and lines[1].isdigit() else 0
                    })

        self.data['important_paths'] = paths
        return paths

    def _get_recently_modified(self) -> List[Dict]:
        """Get recently modified configuration files"""
        files = []

        exit_code, stdout, _ = self.ssh.execute(
            "find /etc -type f -mtime -30 -ls 2>/dev/null | head -50",
            use_sudo=True
        )

        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    files.append({
                        'path': parts[10],
                        'size': int(parts[6]) if parts[6].isdigit() else 0,
                        'modified': f"{parts[7]} {parts[8]} {parts[9]}"
                    })

        self.data['recently_modified'] = files
        return files


class RemoteHistoryAnalyzer:
    """Analyzes bash histories on a remote system via SSH"""

    IMPORTANT_PATTERNS = [
        r'(apt|apt-get|yum|dnf|pacman)\s+(install|remove|update|upgrade)',
        r'pip3?\s+install',
        r'npm\s+(install|i)\s+(-g|--global)',
        r'systemctl\s+(enable|disable|start|stop|restart)',
        r'docker\s+(run|build|pull|compose)',
        r'git\s+(clone|pull)',
        r'(cp|mv|ln)\s+.*\.(conf|cfg|yaml|yml|json)',
        r'useradd|usermod|groupadd',
        r'(iptables|ufw|firewall-cmd)',
        r'crontab',
    ]

    def __init__(self, ssh: SSHExecutor, users: List[str] = None):
        self.ssh = ssh
        self.users = users or []
        self.data = {
            'commands': [],
            'setup_commands': [],
            'package_installations': [],
            'service_changes': [],
            'config_changes': [],
            'users_analyzed': []
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full history analysis on remote system"""
        users_to_check = self._get_users_to_analyze()
        self.data['users_analyzed'] = users_to_check

        all_commands = []

        for user in users_to_check:
            commands = self._read_user_history(user)
            all_commands.extend(commands)

        # Also check root
        root_commands = self._read_user_history('root')
        all_commands.extend(root_commands)

        self.data['commands'] = all_commands
        self._categorize_commands(all_commands)

        return self.data

    def _get_users_to_analyze(self) -> List[str]:
        """Get list of users to analyze"""
        if self.users:
            return self.users

        users = []
        content = self.ssh.read_file('/etc/passwd', use_sudo=False)

        if content:
            for line in content.split('\n'):
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    shell = parts[6]
                    if shell in ['/bin/bash', '/bin/zsh', '/bin/sh']:
                        users.append(username)

        return users[:10]  # Limit to 10 users

    def _read_user_history(self, user: str) -> List[Dict]:
        """Read bash history for a user"""
        commands = []

        if user == 'root':
            home = '/root'
        else:
            home = f'/home/{user}'

        history_files = [
            f'{home}/.bash_history',
            f'{home}/.zsh_history',
        ]

        for history_file in history_files:
            content = self.ssh.read_file(history_file, use_sudo=True)
            if content:
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Handle zsh history format
                    if line.startswith(':'):
                        match = re.match(r':\s*\d+:\d+;(.+)', line)
                        if match:
                            line = match.group(1)

                    commands.append({
                        'command': line,
                        'user': user,
                        'source': history_file,
                        'line': line_num
                    })

        return commands

    def _categorize_commands(self, commands: List[Dict]) -> None:
        """Categorize commands by type"""
        setup_commands = []
        package_installations = []
        service_changes = []
        config_changes = []

        for cmd_info in commands:
            cmd = cmd_info['command']

            for pattern in self.IMPORTANT_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    setup_commands.append(cmd_info)

                    if re.search(r'(apt|yum|dnf|pip|npm)\s+install', cmd, re.IGNORECASE):
                        package_installations.append(cmd_info)
                    elif re.search(r'systemctl|service', cmd, re.IGNORECASE):
                        service_changes.append(cmd_info)
                    elif re.search(r'/etc/|\.conf|\.cfg|\.yaml', cmd, re.IGNORECASE):
                        config_changes.append(cmd_info)
                    break

        # Deduplicate
        seen = set()
        self.data['setup_commands'] = [c for c in setup_commands if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['package_installations'] = [c for c in package_installations if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['service_changes'] = [c for c in service_changes if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['config_changes'] = [c for c in config_changes if c['command'] not in seen and not seen.add(c['command'])]


class RemoteSecretsAnalyzer:
    """Analyzes private keys and GPG keyrings on a remote system via SSH"""

    def __init__(self, ssh: SSHExecutor):
        self.ssh = ssh
        self.data = {
            'ssh_keys': [],
            'gpg_keyrings': [],
            'other_keys': [],
            'authorized_keys': [],
            'known_hosts': []
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full secrets analysis on remote system"""
        self._find_ssh_keys()
        self._find_gpg_keyrings()
        self._find_other_keys()
        self._get_authorized_keys()
        self._get_known_hosts()
        return self.data

    def _find_ssh_keys(self) -> List[Dict]:
        """Find SSH private keys on the system"""
        keys = []

        # Common SSH key locations
        key_patterns = [
            '/root/.ssh/id_*',
            '/home/*/.ssh/id_*',
            '/etc/ssh/ssh_host_*_key',
        ]

        # Find private keys
        exit_code, stdout, _ = self.ssh.execute(
            "find /root/.ssh /home/*/.ssh /etc/ssh -name 'id_*' -o -name 'ssh_host_*_key' 2>/dev/null | grep -v '.pub$'",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for key_path in stdout.strip().split('\n'):
                if key_path and not key_path.endswith('.pub'):
                    key_info = self._get_key_info(key_path)
                    if key_info:
                        keys.append(key_info)

        # Also search for keys by content pattern
        exit_code, stdout, _ = self.ssh.execute(
            "grep -rl 'PRIVATE KEY' /root/.ssh /home/*/.ssh /etc/ssh 2>/dev/null | head -20",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for key_path in stdout.strip().split('\n'):
                if key_path and not any(k['path'] == key_path for k in keys):
                    key_info = self._get_key_info(key_path)
                    if key_info:
                        keys.append(key_info)

        self.data['ssh_keys'] = keys
        return keys

    def _get_key_info(self, path: str) -> Optional[Dict]:
        """Get information about a key file"""
        exit_code, stdout, _ = self.ssh.execute(
            f"ls -la '{path}' 2>/dev/null && head -1 '{path}' 2>/dev/null",
            use_sudo=True
        )

        if exit_code != 0:
            return None

        lines = stdout.strip().split('\n')
        if not lines:
            return None

        # Parse ls output
        ls_parts = lines[0].split()
        if len(ls_parts) < 9:
            return None

        key_type = 'unknown'
        if len(lines) > 1:
            header = lines[1]
            if 'RSA' in header:
                key_type = 'RSA'
            elif 'EC' in header or 'ECDSA' in header:
                key_type = 'ECDSA'
            elif 'ED25519' in header or 'OPENSSH' in header:
                key_type = 'ED25519'
            elif 'DSA' in header:
                key_type = 'DSA'
            elif 'ENCRYPTED' in header:
                key_type = 'encrypted'

        # Check if key has a passphrase (encrypted)
        encrypted = 'ENCRYPTED' in stdout

        # Determine owner from path
        if path.startswith('/root/'):
            owner = 'root'
        elif path.startswith('/home/'):
            owner = path.split('/')[2]
        elif path.startswith('/etc/ssh'):
            owner = 'system (host key)'
        else:
            owner = ls_parts[2]

        # Check for corresponding .pub file
        has_pub = False
        exit_code, _, _ = self.ssh.execute(f"test -f '{path}.pub'", use_sudo=True)
        if exit_code == 0:
            has_pub = True

        return {
            'path': path,
            'type': key_type,
            'owner': owner,
            'permissions': ls_parts[0],
            'encrypted': encrypted,
            'has_public_key': has_pub,
            'is_host_key': '/etc/ssh' in path
        }

    def _find_gpg_keyrings(self) -> List[Dict]:
        """Find GPG keyrings on the system"""
        keyrings = []

        # Find GPG directories
        exit_code, stdout, _ = self.ssh.execute(
            "find /root /home -name '.gnupg' -type d 2>/dev/null",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for gpg_dir in stdout.strip().split('\n'):
                if gpg_dir:
                    keyring_info = self._get_gpg_info(gpg_dir)
                    if keyring_info:
                        keyrings.append(keyring_info)

        self.data['gpg_keyrings'] = keyrings
        return keyrings

    def _get_gpg_info(self, gpg_dir: str) -> Optional[Dict]:
        """Get information about a GPG keyring"""
        # Get owner from path
        if gpg_dir.startswith('/root/'):
            owner = 'root'
        elif gpg_dir.startswith('/home/'):
            owner = gpg_dir.split('/')[2]
        else:
            owner = 'unknown'

        # List keys in the keyring
        exit_code, stdout, _ = self.ssh.execute(
            f"GNUPGHOME='{gpg_dir}' gpg --list-keys --keyid-format SHORT 2>/dev/null | head -50",
            use_sudo=True
        )

        public_keys = []
        if exit_code == 0 and stdout.strip():
            # Parse GPG output
            current_key = None
            for line in stdout.strip().split('\n'):
                if line.startswith('pub'):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_key = {'id': parts[1], 'type': 'public'}
                elif line.startswith('uid') and current_key:
                    uid = line.replace('uid', '').strip()
                    # Remove trust level markers like [ultimate]
                    uid = re.sub(r'\[.*?\]', '', uid).strip()
                    current_key['uid'] = uid
                    public_keys.append(current_key)
                    current_key = None

        # List secret keys
        exit_code, stdout, _ = self.ssh.execute(
            f"GNUPGHOME='{gpg_dir}' gpg --list-secret-keys --keyid-format SHORT 2>/dev/null | head -50",
            use_sudo=True
        )

        secret_keys = []
        if exit_code == 0 and stdout.strip():
            current_key = None
            for line in stdout.strip().split('\n'):
                if line.startswith('sec'):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_key = {'id': parts[1], 'type': 'secret'}
                elif line.startswith('uid') and current_key:
                    uid = line.replace('uid', '').strip()
                    uid = re.sub(r'\[.*?\]', '', uid).strip()
                    current_key['uid'] = uid
                    secret_keys.append(current_key)
                    current_key = None

        # Get directory size
        exit_code, stdout, _ = self.ssh.execute(
            f"du -sh '{gpg_dir}' 2>/dev/null",
            use_sudo=True
        )
        size = stdout.split()[0] if exit_code == 0 and stdout.strip() else 'unknown'

        return {
            'path': gpg_dir,
            'owner': owner,
            'size': size,
            'public_keys': public_keys,
            'secret_keys': secret_keys,
            'key_count': len(public_keys),
            'secret_key_count': len(secret_keys)
        }

    def _find_other_keys(self) -> List[Dict]:
        """Find other key/certificate files"""
        keys = []

        # Search for PEM, key, and certificate files in common locations
        exit_code, stdout, _ = self.ssh.execute(
            "find /etc/ssl /etc/pki /opt -type f \\( -name '*.pem' -o -name '*.key' -o -name '*.crt' \\) 2>/dev/null | head -30",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for path in stdout.strip().split('\n'):
                if path:
                    # Check if it's a private key
                    exit_code, content, _ = self.ssh.execute(
                        f"head -1 '{path}' 2>/dev/null",
                        use_sudo=True
                    )
                    if exit_code == 0 and content.strip():
                        is_private = 'PRIVATE' in content
                        is_cert = 'CERTIFICATE' in content

                        keys.append({
                            'path': path,
                            'is_private_key': is_private,
                            'is_certificate': is_cert,
                            'type': 'private_key' if is_private else 'certificate' if is_cert else 'unknown'
                        })

        self.data['other_keys'] = keys
        return keys

    def _get_authorized_keys(self) -> List[Dict]:
        """Get authorized_keys information"""
        auth_keys = []

        # Find all authorized_keys files
        exit_code, stdout, _ = self.ssh.execute(
            "find /root/.ssh /home/*/.ssh -name 'authorized_keys' 2>/dev/null",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for auth_file in stdout.strip().split('\n'):
                if auth_file:
                    exit_code, content, _ = self.ssh.execute(
                        f"wc -l < '{auth_file}' && cat '{auth_file}' 2>/dev/null",
                        use_sudo=True
                    )

                    if exit_code == 0 and content.strip():
                        lines = content.strip().split('\n')
                        key_count = int(lines[0]) if lines[0].isdigit() else 0

                        # Parse key comments/identifiers
                        key_ids = []
                        for line in lines[1:]:
                            if line.strip() and not line.startswith('#'):
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    key_ids.append(parts[-1])  # Usually the comment/email
                                elif len(parts) == 2:
                                    key_ids.append(parts[0][:20] + '...')  # Key type abbreviated

                        # Determine owner from path
                        if auth_file.startswith('/root/'):
                            owner = 'root'
                        elif auth_file.startswith('/home/'):
                            owner = auth_file.split('/')[2]
                        else:
                            owner = 'unknown'

                        auth_keys.append({
                            'path': auth_file,
                            'owner': owner,
                            'key_count': key_count,
                            'key_identifiers': key_ids[:10]  # Limit to 10
                        })

        self.data['authorized_keys'] = auth_keys
        return auth_keys

    def _get_known_hosts(self) -> List[Dict]:
        """Get known_hosts summary"""
        known = []

        # Find all known_hosts files
        exit_code, stdout, _ = self.ssh.execute(
            "find /root/.ssh /home/*/.ssh -name 'known_hosts' 2>/dev/null",
            use_sudo=True
        )

        if exit_code == 0 and stdout.strip():
            for kh_file in stdout.strip().split('\n'):
                if kh_file:
                    exit_code, content, _ = self.ssh.execute(
                        f"wc -l < '{kh_file}'",
                        use_sudo=True
                    )

                    if exit_code == 0 and content.strip():
                        host_count = int(content.strip()) if content.strip().isdigit() else 0

                        # Determine owner from path
                        if kh_file.startswith('/root/'):
                            owner = 'root'
                        elif kh_file.startswith('/home/'):
                            owner = kh_file.split('/')[2]
                        else:
                            owner = 'unknown'

                        known.append({
                            'path': kh_file,
                            'owner': owner,
                            'host_count': host_count
                        })

        self.data['known_hosts'] = known
        return known


class RemoteSystemAnalyzer:
    """Orchestrates all remote analysis"""

    def __init__(self, ssh: SSHExecutor):
        self.ssh = ssh
        self.hostname = ssh.get_hostname()

    def analyze_all(self, users: List[str] = None) -> Dict[str, Any]:
        """Run complete analysis on remote system"""
        logger.info(f"Starting analysis of {self.hostname}")

        data = {
            'hostname': self.hostname,
            'os_info': self.ssh.get_os_info(),
            'processes': {},
            'files': {},
            'history': {},
            'secrets': {}
        }

        # Process analysis
        logger.info("Analyzing processes...")
        process_analyzer = RemoteProcessAnalyzer(self.ssh)
        data['processes'] = process_analyzer.analyze()

        # File analysis
        logger.info("Analyzing files and packages...")
        file_analyzer = RemoteFileAnalyzer(self.ssh)
        data['files'] = file_analyzer.analyze()

        # History analysis
        logger.info("Analyzing bash histories...")
        history_analyzer = RemoteHistoryAnalyzer(self.ssh, users)
        data['history'] = history_analyzer.analyze()

        # Secrets analysis (SSH keys, GPG keyrings)
        logger.info("Analyzing SSH keys and GPG keyrings...")
        secrets_analyzer = RemoteSecretsAnalyzer(self.ssh)
        data['secrets'] = secrets_analyzer.analyze()

        logger.info(f"Analysis of {self.hostname} complete")
        return data
