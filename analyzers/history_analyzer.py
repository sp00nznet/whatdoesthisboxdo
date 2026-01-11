"""
History Analyzer
Analyzes bash histories to find relevant system setup commands
"""

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class HistoryAnalyzer:
    """Analyzes bash histories for system setup and configuration commands"""

    # Patterns for important commands
    IMPORTANT_PATTERNS = [
        # Package management
        r'(apt|apt-get|yum|dnf|pacman|zypper)\s+(install|remove|update|upgrade)',
        r'pip3?\s+install',
        r'npm\s+(install|i)\s+(-g|--global)',
        r'gem\s+install',
        r'cargo\s+install',

        # Service management
        r'systemctl\s+(enable|disable|start|stop|restart)',
        r'service\s+\w+\s+(start|stop|restart|enable)',

        # Docker
        r'docker\s+(run|build|pull|compose)',
        r'docker-compose\s+(up|down|build)',

        # Kubernetes
        r'kubectl\s+(apply|create|delete)',
        r'helm\s+(install|upgrade)',

        # Configuration
        r'(cp|mv|ln)\s+.*\.(conf|cfg|yaml|yml|json)',
        r'(vim|vi|nano|cat\s*>)\s+.*/etc/',
        r'echo\s+.*>>\s*/etc/',

        # User management
        r'useradd|usermod|groupadd',
        r'passwd\s+\w+',
        r'chown|chmod',

        # Network configuration
        r'(iptables|ufw|firewall-cmd)',
        r'ip\s+(addr|route|link)',
        r'netplan\s+apply',

        # Disk/Storage
        r'(fdisk|parted|lvm|mount|fstab)',
        r'mkfs\.',

        # Git operations (for deployment info)
        r'git\s+(clone|pull|checkout)',

        # SSH/Security
        r'ssh-keygen',
        r'authorized_keys',

        # Cron
        r'crontab\s+-[el]',

        # Environment setup
        r'export\s+\w+=',
        r'source\s+',
        r'\.\s+.*profile',
    ]

    def __init__(self, users: List[str] = None):
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
        """Run full history analysis"""
        # Get users to analyze
        users_to_check = self._get_users_to_analyze()
        self.data['users_analyzed'] = users_to_check

        # Collect all history
        all_commands = []
        for user in users_to_check:
            commands = self._read_user_history(user)
            all_commands.extend(commands)

        # Also check root history
        root_commands = self._read_user_history('root')
        all_commands.extend(root_commands)

        self.data['commands'] = all_commands

        # Categorize commands
        self._categorize_commands(all_commands)

        return self.data

    def _get_users_to_analyze(self) -> List[str]:
        """Get list of users to analyze"""
        if self.users:
            return self.users

        # Get users with login shells
        users = []
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        shell = parts[6]
                        home = parts[5]

                        # Skip system users
                        if shell in ['/bin/bash', '/bin/zsh', '/bin/sh']:
                            if os.path.exists(home):
                                users.append(username)
        except Exception as e:
            logger.warning(f"Could not read /etc/passwd: {e}")

        return users

    def _read_user_history(self, user: str) -> List[Dict]:
        """Read bash history for a user"""
        commands = []

        # Determine home directory
        if user == 'root':
            home = '/root'
        else:
            home = f'/home/{user}'

        history_files = [
            f'{home}/.bash_history',
            f'{home}/.zsh_history',
            f'{home}/.history'
        ]

        for history_file in history_files:
            if os.path.exists(history_file):
                try:
                    commands.extend(self._parse_history_file(history_file, user))
                except PermissionError:
                    # Try with sudo
                    commands.extend(self._read_with_sudo(history_file, user))
                except Exception as e:
                    logger.debug(f"Could not read {history_file}: {e}")

        return commands

    def _parse_history_file(self, filepath: str, user: str) -> List[Dict]:
        """Parse a history file"""
        commands = []

        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Handle zsh history format (: timestamp:0;command)
                    if line.startswith(':'):
                        match = re.match(r':\s*(\d+):\d+;(.+)', line)
                        if match:
                            line = match.group(2)

                    commands.append({
                        'command': line,
                        'user': user,
                        'source': filepath,
                        'line': line_num
                    })
        except Exception as e:
            logger.debug(f"Error parsing {filepath}: {e}")

        return commands

    def _read_with_sudo(self, filepath: str, user: str) -> List[Dict]:
        """Try to read history file with sudo"""
        commands = []

        try:
            result = subprocess.run(
                ['sudo', 'cat', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                for line_num, line in enumerate(result.stdout.split('\n'), 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    commands.append({
                        'command': line,
                        'user': user,
                        'source': filepath,
                        'line': line_num
                    })
        except Exception as e:
            logger.debug(f"Could not read {filepath} with sudo: {e}")

        return commands

    def _categorize_commands(self, commands: List[Dict]) -> None:
        """Categorize commands by type"""
        setup_commands = []
        package_installations = []
        service_changes = []
        config_changes = []

        for cmd_info in commands:
            cmd = cmd_info['command']

            # Check if it matches any important pattern
            is_important = False
            for pattern in self.IMPORTANT_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    is_important = True
                    setup_commands.append(cmd_info)

                    # Further categorize
                    if re.search(r'(apt|yum|dnf|pip|npm|gem)\s+install', cmd, re.IGNORECASE):
                        package_installations.append(cmd_info)
                    elif re.search(r'systemctl|service', cmd, re.IGNORECASE):
                        service_changes.append(cmd_info)
                    elif re.search(r'/etc/|\.conf|\.cfg|\.yaml', cmd, re.IGNORECASE):
                        config_changes.append(cmd_info)

                    break

        # Remove duplicates while preserving order
        seen = set()
        unique_setup = []
        for cmd in setup_commands:
            if cmd['command'] not in seen:
                seen.add(cmd['command'])
                unique_setup.append(cmd)

        self.data['setup_commands'] = unique_setup
        self.data['package_installations'] = self._dedupe(package_installations)
        self.data['service_changes'] = self._dedupe(service_changes)
        self.data['config_changes'] = self._dedupe(config_changes)

    def _dedupe(self, commands: List[Dict]) -> List[Dict]:
        """Remove duplicate commands"""
        seen = set()
        unique = []
        for cmd in commands:
            if cmd['command'] not in seen:
                seen.add(cmd['command'])
                unique.append(cmd)
        return unique

    def get_installation_sequence(self) -> List[str]:
        """Get a logical sequence of installation commands"""
        sequence = []

        # Order by type
        order = [
            ('System updates', r'(apt|yum|dnf)\s+(update|upgrade)'),
            ('Package installations', r'(apt|yum|dnf|apt-get)\s+install'),
            ('Python packages', r'pip3?\s+install'),
            ('Node packages', r'npm\s+install'),
            ('User setup', r'(useradd|usermod|groupadd)'),
            ('Service configuration', r'systemctl\s+(enable|start)'),
            ('Configuration changes', r'(cp|mv|ln|vim|nano|cat).*\.(conf|cfg|yaml)'),
        ]

        for category, pattern in order:
            matching = []
            for cmd in self.data['setup_commands']:
                if re.search(pattern, cmd['command'], re.IGNORECASE):
                    matching.append(cmd['command'])

            if matching:
                sequence.append({
                    'category': category,
                    'commands': list(dict.fromkeys(matching))  # Preserve order, remove dupes
                })

        return sequence

    def extract_package_list(self) -> Dict[str, List[str]]:
        """Extract lists of installed packages by package manager"""
        packages = {
            'apt': [],
            'yum': [],
            'pip': [],
            'npm': [],
            'other': []
        }

        for cmd in self.data['package_installations']:
            command = cmd['command']

            # apt/apt-get
            match = re.search(r'(apt|apt-get)\s+install\s+(-y\s+)?(.+)', command)
            if match:
                pkgs = match.group(3).split()
                packages['apt'].extend([p for p in pkgs if not p.startswith('-')])
                continue

            # yum/dnf
            match = re.search(r'(yum|dnf)\s+install\s+(-y\s+)?(.+)', command)
            if match:
                pkgs = match.group(3).split()
                packages['yum'].extend([p for p in pkgs if not p.startswith('-')])
                continue

            # pip
            match = re.search(r'pip3?\s+install\s+(.+)', command)
            if match:
                pkgs = match.group(1).split()
                packages['pip'].extend([p for p in pkgs if not p.startswith('-')])
                continue

            # npm
            match = re.search(r'npm\s+(?:install|i)\s+(?:-g\s+)?(.+)', command)
            if match:
                pkgs = match.group(1).split()
                packages['npm'].extend([p for p in pkgs if not p.startswith('-')])

        # Remove duplicates
        for key in packages:
            packages[key] = list(dict.fromkeys(packages[key]))

        return packages
