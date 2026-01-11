"""
File Analyzer
Analyzes files being processed, configurations, and important system files
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class FileAnalyzer:
    """Analyzes files and configurations on the system"""

    # Common configuration directories
    CONFIG_DIRS = [
        '/etc',
        '/opt',
        '/var/www',
        '/var/lib',
        '/home',
        '/root'
    ]

    # Important configuration file patterns
    CONFIG_PATTERNS = [
        '*.conf',
        '*.cfg',
        '*.ini',
        '*.yaml',
        '*.yml',
        '*.json',
        '*.xml',
        '*.properties',
        '*.env',
        '.env*'
    ]

    # Service-specific paths to check
    SERVICE_PATHS = {
        'nginx': ['/etc/nginx', '/var/log/nginx'],
        'apache': ['/etc/apache2', '/etc/httpd', '/var/log/apache2', '/var/log/httpd'],
        'mysql': ['/etc/mysql', '/var/lib/mysql', '/var/log/mysql'],
        'postgres': ['/etc/postgresql', '/var/lib/postgresql', '/var/log/postgresql'],
        'docker': ['/etc/docker', '/var/lib/docker'],
        'kubernetes': ['/etc/kubernetes', '/var/lib/kubelet'],
        'systemd': ['/etc/systemd', '/lib/systemd'],
        'ssh': ['/etc/ssh'],
        'cron': ['/etc/cron.d', '/etc/crontab', '/var/spool/cron']
    }

    def __init__(self):
        self.data = {
            'configurations': [],
            'service_configs': {},
            'open_files': [],
            'recently_modified': [],
            'important_paths': [],
            'installed_packages': []
        }

    def analyze(self, additional_paths: List[str] = None) -> Dict[str, Any]:
        """Run full file analysis"""
        paths = self.CONFIG_DIRS.copy()
        if additional_paths:
            paths.extend(additional_paths)

        self._find_config_files(paths)
        self._analyze_service_configs()
        self._get_recently_modified()
        self._get_installed_packages()
        self._find_important_paths()

        return self.data

    def _find_config_files(self, paths: List[str]) -> List[Dict]:
        """Find configuration files in specified paths"""
        configs = []

        for base_path in paths:
            if not os.path.exists(base_path):
                continue

            for pattern in self.CONFIG_PATTERNS:
                try:
                    result = subprocess.run(
                        ['find', base_path, '-name', pattern, '-type', 'f',
                         '-readable', '-size', '-1M', '2>/dev/null'],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        shell=False
                    )

                    for filepath in result.stdout.strip().split('\n'):
                        if filepath and os.path.isfile(filepath):
                            try:
                                stat = os.stat(filepath)
                                configs.append({
                                    'path': filepath,
                                    'size': stat.st_size,
                                    'modified': stat.st_mtime,
                                    'owner': self._get_owner(filepath),
                                    'permissions': oct(stat.st_mode)[-3:]
                                })
                            except (OSError, PermissionError):
                                pass
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout searching {base_path} for {pattern}")
                except Exception as e:
                    logger.debug(f"Error searching {base_path}: {e}")

        self.data['configurations'] = configs
        return configs

    def _analyze_service_configs(self) -> Dict[str, List]:
        """Analyze service-specific configuration files"""
        service_configs = {}

        for service, paths in self.SERVICE_PATHS.items():
            service_configs[service] = []

            for path in paths:
                if os.path.exists(path):
                    service_configs[service].append({
                        'path': path,
                        'exists': True,
                        'files': self._list_dir_contents(path)
                    })

        # Filter out services with no existing paths
        self.data['service_configs'] = {
            k: v for k, v in service_configs.items() if v
        }
        return self.data['service_configs']

    def _list_dir_contents(self, path: str, max_depth: int = 2) -> List[Dict]:
        """List directory contents up to max depth"""
        contents = []

        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    stat = os.stat(item_path)
                    item_info = {
                        'name': item,
                        'path': item_path,
                        'type': 'directory' if os.path.isdir(item_path) else 'file',
                        'size': stat.st_size,
                        'modified': stat.st_mtime
                    }

                    if os.path.isdir(item_path) and max_depth > 1:
                        item_info['contents'] = self._list_dir_contents(item_path, max_depth - 1)

                    contents.append(item_info)
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError):
            pass

        return contents

    def _get_recently_modified(self, days: int = 7) -> List[Dict]:
        """Find recently modified files in important directories"""
        recently_modified = []

        try:
            result = subprocess.run(
                ['find', '/etc', '/opt', '/var', '-type', 'f',
                 '-mtime', f'-{days}', '-readable'],
                capture_output=True,
                text=True,
                timeout=120
            )

            for filepath in result.stdout.strip().split('\n')[:100]:  # Limit to 100 files
                if filepath and os.path.isfile(filepath):
                    try:
                        stat = os.stat(filepath)
                        recently_modified.append({
                            'path': filepath,
                            'modified': stat.st_mtime,
                            'size': stat.st_size
                        })
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            logger.warning(f"Error finding recently modified files: {e}")

        self.data['recently_modified'] = recently_modified
        return recently_modified

    def _get_installed_packages(self) -> List[Dict]:
        """Get list of installed packages"""
        packages = []

        # Try dpkg (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ['dpkg-query', '-W', '-f', '${Package}|${Version}|${Status}\n'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split('|')
                    if len(parts) >= 3 and 'installed' in parts[2]:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'manager': 'dpkg'
                        })
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"dpkg error: {e}")

        # Try rpm (RHEL/CentOS/Fedora)
        if not packages:
            try:
                result = subprocess.run(
                    ['rpm', '-qa', '--queryformat', '%{NAME}|%{VERSION}\n'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        parts = line.split('|')
                        if len(parts) >= 2:
                            packages.append({
                                'name': parts[0],
                                'version': parts[1],
                                'manager': 'rpm'
                            })
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"rpm error: {e}")

        # Also check pip packages
        try:
            result = subprocess.run(
                ['pip3', 'list', '--format=json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                import json
                pip_packages = json.loads(result.stdout)
                for pkg in pip_packages:
                    packages.append({
                        'name': pkg['name'],
                        'version': pkg['version'],
                        'manager': 'pip'
                    })
        except Exception as e:
            logger.debug(f"pip error: {e}")

        self.data['installed_packages'] = packages
        return packages

    def _find_important_paths(self) -> List[Dict]:
        """Find important paths like data directories, logs, etc."""
        important = []

        # Check common important paths
        paths_to_check = [
            '/var/log',
            '/var/www',
            '/var/lib',
            '/opt',
            '/srv',
            '/data',
            '/backup',
            '/home'
        ]

        for path in paths_to_check:
            if os.path.exists(path):
                try:
                    # Get directory size
                    result = subprocess.run(
                        ['du', '-sh', path],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    size = result.stdout.split()[0] if result.stdout else 'unknown'

                    important.append({
                        'path': path,
                        'size': size,
                        'type': 'directory',
                        'contents_count': len(os.listdir(path)) if os.path.isdir(path) else 0
                    })
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")

        self.data['important_paths'] = important
        return important

    def _get_owner(self, filepath: str) -> str:
        """Get file owner"""
        try:
            import pwd
            stat = os.stat(filepath)
            return pwd.getpwuid(stat.st_uid).pw_name
        except Exception:
            return 'unknown'

    def read_config_file(self, filepath: str, max_lines: int = 100) -> Optional[str]:
        """Read contents of a configuration file safely"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines)
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot read {filepath}: {e}")
            return None

    def get_cron_jobs(self) -> List[Dict]:
        """Get scheduled cron jobs"""
        cron_jobs = []

        # System crontab
        cron_files = [
            '/etc/crontab',
            '/etc/cron.d',
        ]

        for cron_path in cron_files:
            if os.path.isfile(cron_path):
                content = self.read_config_file(cron_path)
                if content:
                    cron_jobs.append({
                        'source': cron_path,
                        'content': content
                    })
            elif os.path.isdir(cron_path):
                for item in os.listdir(cron_path):
                    item_path = os.path.join(cron_path, item)
                    content = self.read_config_file(item_path)
                    if content:
                        cron_jobs.append({
                            'source': item_path,
                            'content': content
                        })

        # User crontabs
        try:
            result = subprocess.run(
                ['ls', '/var/spool/cron/crontabs/'],
                capture_output=True,
                text=True,
                timeout=10
            )
            for user in result.stdout.strip().split('\n'):
                if user:
                    cron_jobs.append({
                        'source': f'/var/spool/cron/crontabs/{user}',
                        'user': user,
                        'type': 'user_crontab'
                    })
        except Exception:
            pass

        return cron_jobs

    def get_systemd_units(self) -> List[Dict]:
        """Get custom systemd unit files"""
        units = []
        unit_dirs = [
            '/etc/systemd/system',
            '/usr/local/lib/systemd/system'
        ]

        for unit_dir in unit_dirs:
            if os.path.isdir(unit_dir):
                for item in os.listdir(unit_dir):
                    if item.endswith(('.service', '.timer', '.socket')):
                        item_path = os.path.join(unit_dir, item)
                        if os.path.isfile(item_path):
                            units.append({
                                'name': item,
                                'path': item_path,
                                'content': self.read_config_file(item_path)
                            })

        return units
