"""
Process Analyzer
Analyzes running processes, services, and network connections
"""

import logging
import subprocess
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available, using fallback methods")


class ProcessAnalyzer:
    """Analyzes running processes and services on the system"""

    def __init__(self):
        self.data = {
            'running': [],
            'services': [],
            'connections': [],
            'listening_ports': [],
            'resource_usage': {}
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full process analysis"""
        self._get_running_processes()
        self._get_services()
        self._get_connections()
        self._get_resource_usage()
        return self.data

    def _get_running_processes(self) -> List[Dict]:
        """Get list of running processes with details"""
        if PSUTIL_AVAILABLE:
            return self._get_processes_psutil()
        return self._get_processes_fallback()

    def _get_processes_psutil(self) -> List[Dict]:
        """Get processes using psutil"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline',
                                          'cpu_percent', 'memory_percent',
                                          'status', 'create_time', 'exe']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'user': pinfo['username'],
                    'cmdline': ' '.join(pinfo['cmdline'] or []),
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': round(pinfo['memory_percent'], 2) if pinfo['memory_percent'] else 0,
                    'status': pinfo['status'],
                    'exe': pinfo['exe']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        self.data['running'] = processes
        return processes

    def _get_processes_fallback(self) -> List[Dict]:
        """Get processes using ps command fallback"""
        try:
            result = subprocess.run(
                ['ps', 'aux', '--no-headers'],
                capture_output=True,
                text=True,
                timeout=30
            )
            processes = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': int(parts[1]),
                            'cpu_percent': float(parts[2]),
                            'memory_percent': float(parts[3]),
                            'status': parts[7],
                            'name': parts[10].split()[0] if parts[10] else '',
                            'cmdline': parts[10]
                        })
            self.data['running'] = processes
            return processes
        except Exception as e:
            logger.error(f"Failed to get processes: {e}")
            return []

    def _get_services(self) -> List[Dict]:
        """Get systemd services"""
        services = []
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend'],
                capture_output=True,
                text=True,
                timeout=30
            )
            for line in result.stdout.strip().split('\n'):
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
        except Exception as e:
            logger.error(f"Failed to get services: {e}")

        self.data['services'] = services
        return services

    def _get_connections(self) -> List[Dict]:
        """Get network connections"""
        connections = []

        if PSUTIL_AVAILABLE:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else 'unknown'
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = 'unknown'

                    connections.append({
                        'process': proc_name,
                        'pid': conn.pid,
                        'local_addr': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_addr': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'type': 'tcp' if conn.type == 1 else 'udp'
                    })
            except (psutil.AccessDenied, Exception) as e:
                logger.warning(f"Could not get connections via psutil: {e}")
                connections = self._get_connections_fallback()
        else:
            connections = self._get_connections_fallback()

        # Extract listening ports
        self.data['listening_ports'] = [
            {'port': c['local_port'], 'process': c['process'], 'addr': c['local_addr']}
            for c in connections if c['status'] == 'LISTEN'
        ]

        self.data['connections'] = connections
        return connections

    def _get_connections_fallback(self) -> List[Dict]:
        """Get connections using ss command"""
        connections = []
        try:
            result = subprocess.run(
                ['ss', '-tunapH'],
                capture_output=True,
                text=True,
                timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local = parts[4].rsplit(':', 1)
                        remote = parts[5].rsplit(':', 1) if len(parts) > 5 else ['', '0']
                        connections.append({
                            'type': parts[0],
                            'status': parts[1],
                            'local_addr': local[0] if local else '',
                            'local_port': int(local[1]) if len(local) > 1 and local[1].isdigit() else 0,
                            'remote_addr': remote[0] if remote else '',
                            'remote_port': int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                            'process': parts[-1] if len(parts) > 6 else 'unknown'
                        })
        except Exception as e:
            logger.error(f"Failed to get connections: {e}")

        return connections

    def _get_resource_usage(self) -> Dict:
        """Get system resource usage"""
        usage = {}

        if PSUTIL_AVAILABLE:
            usage = {
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'count': psutil.cpu_count(),
                    'load_avg': list(psutil.getloadavg())
                },
                'memory': dict(psutil.virtual_memory()._asdict()),
                'disk': {},
                'network': {}
            }

            # Disk usage
            for partition in psutil.disk_partitions():
                try:
                    usage_info = psutil.disk_usage(partition.mountpoint)
                    usage['disk'][partition.mountpoint] = {
                        'total': usage_info.total,
                        'used': usage_info.used,
                        'free': usage_info.free,
                        'percent': usage_info.percent
                    }
                except (PermissionError, OSError):
                    pass

            # Network I/O
            net_io = psutil.net_io_counters()
            usage['network'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        else:
            # Fallback using system commands
            try:
                # CPU
                with open('/proc/loadavg', 'r') as f:
                    load = f.read().split()[:3]
                    usage['cpu'] = {'load_avg': [float(x) for x in load]}

                # Memory
                result = subprocess.run(['free', '-b'], capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    mem_parts = lines[1].split()
                    usage['memory'] = {
                        'total': int(mem_parts[1]),
                        'used': int(mem_parts[2]),
                        'free': int(mem_parts[3])
                    }

                # Disk
                result = subprocess.run(['df', '-B1'], capture_output=True, text=True)
                usage['disk'] = {}
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        usage['disk'][parts[5]] = {
                            'total': int(parts[1]),
                            'used': int(parts[2]),
                            'free': int(parts[3])
                        }
            except Exception as e:
                logger.error(f"Failed to get resource usage: {e}")

        self.data['resource_usage'] = usage
        return usage

    def get_process_tree(self) -> Dict:
        """Get process tree structure"""
        if not PSUTIL_AVAILABLE:
            return {}

        tree = {}
        for proc in psutil.process_iter(['pid', 'ppid', 'name']):
            try:
                pinfo = proc.info
                tree[pinfo['pid']] = {
                    'name': pinfo['name'],
                    'ppid': pinfo['ppid'],
                    'children': []
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Build tree structure
        for pid, info in tree.items():
            ppid = info['ppid']
            if ppid in tree:
                tree[ppid]['children'].append(pid)

        return tree

    def get_open_files(self) -> List[Dict]:
        """Get open files by processes"""
        if not PSUTIL_AVAILABLE:
            return []

        open_files = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for f in proc.open_files():
                    open_files.append({
                        'pid': proc.info['pid'],
                        'process': proc.info['name'],
                        'path': f.path,
                        'mode': f.mode
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return open_files
