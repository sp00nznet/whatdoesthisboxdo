"""
Proxmox Connector
Connects to Proxmox VE to get VM/container information
"""

import logging
from typing import Dict, List, Any, Optional
import urllib3

logger = logging.getLogger(__name__)

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available")

try:
    from proxmoxer import ProxmoxAPI
    PROXMOXER_AVAILABLE = True
except ImportError:
    PROXMOXER_AVAILABLE = False
    logger.warning("proxmoxer not available, using direct API")


class ProxmoxConnector:
    """Connects to Proxmox VE API"""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.proxmox = None
        self.api_token = None
        self.data = {
            'nodes': [],
            'vms': [],
            'containers': [],
            'storage': [],
            'networks': [],
            'current_vm': {}
        }

    def connect(self) -> bool:
        """Establish connection to Proxmox"""
        if PROXMOXER_AVAILABLE:
            return self._connect_proxmoxer()
        elif REQUESTS_AVAILABLE:
            return self._connect_direct()
        else:
            logger.error("No HTTP library available for Proxmox connection")
            return False

    def _connect_proxmoxer(self) -> bool:
        """Connect using proxmoxer library"""
        try:
            self.proxmox = ProxmoxAPI(
                self.host,
                user=self.username,
                password=self.password,
                verify_ssl=self.verify_ssl
            )
            logger.info(f"Connected to Proxmox: {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Proxmox: {e}")
            return False

    def _connect_direct(self) -> bool:
        """Connect using direct API calls"""
        try:
            response = requests.post(
                f"https://{self.host}:8006/api2/json/access/ticket",
                data={
                    'username': self.username,
                    'password': self.password
                },
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()['data']
            self.api_token = {
                'ticket': data['ticket'],
                'csrf': data['CSRFPreventionToken']
            }
            logger.info(f"Connected to Proxmox: {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Proxmox: {e}")
            return False

    def _api_get(self, endpoint: str) -> Optional[Any]:
        """Make API GET request"""
        if PROXMOXER_AVAILABLE and self.proxmox:
            try:
                parts = endpoint.strip('/').split('/')
                obj = self.proxmox
                for part in parts:
                    obj = getattr(obj, part)
                return obj.get()
            except Exception as e:
                logger.debug(f"Proxmox API error: {e}")
                return None
        elif self.api_token:
            try:
                response = requests.get(
                    f"https://{self.host}:8006/api2/json/{endpoint}",
                    cookies={'PVEAuthCookie': self.api_token['ticket']},
                    headers={'CSRFPreventionToken': self.api_token['csrf']},
                    verify=self.verify_ssl,
                    timeout=30
                )
                response.raise_for_status()
                return response.json().get('data')
            except Exception as e:
                logger.debug(f"Proxmox API error: {e}")
                return None
        return None

    def get_vm_info(self) -> Dict[str, Any]:
        """Get comprehensive VM/container information"""
        if not self.connect():
            return {}

        try:
            self._get_nodes()
            self._get_vms()
            self._get_containers()
            self._get_storage()
            self._get_networks()
        except Exception as e:
            logger.error(f"Error getting Proxmox info: {e}")

        return self.data

    def _get_nodes(self) -> List[Dict]:
        """Get Proxmox nodes"""
        nodes = []

        result = self._api_get('nodes')
        if result:
            for node in result:
                nodes.append({
                    'name': node['node'],
                    'status': node['status'],
                    'cpu': node.get('cpu', 0),
                    'maxcpu': node.get('maxcpu', 0),
                    'mem': node.get('mem', 0),
                    'maxmem': node.get('maxmem', 0),
                    'disk': node.get('disk', 0),
                    'maxdisk': node.get('maxdisk', 0),
                    'uptime': node.get('uptime', 0)
                })

        self.data['nodes'] = nodes
        return nodes

    def _get_vms(self) -> List[Dict]:
        """Get all VMs across all nodes"""
        vms = []

        for node in self.data['nodes']:
            node_name = node['name']
            result = self._api_get(f"nodes/{node_name}/qemu")

            if result:
                for vm in result:
                    vm_info = {
                        'vmid': vm['vmid'],
                        'name': vm.get('name', f"VM-{vm['vmid']}"),
                        'node': node_name,
                        'status': vm['status'],
                        'cpu': vm.get('cpus', 1),
                        'mem_mb': vm.get('maxmem', 0) // 1024 // 1024,
                        'disk_gb': vm.get('maxdisk', 0) // 1024 // 1024 // 1024,
                        'uptime': vm.get('uptime', 0),
                        'template': vm.get('template', 0) == 1,
                        'type': 'qemu'
                    }

                    # Get detailed config
                    config = self._api_get(f"nodes/{node_name}/qemu/{vm['vmid']}/config")
                    if config:
                        vm_info.update(self._parse_vm_config(config))

                    vms.append(vm_info)

        self.data['vms'] = vms
        return vms

    def _get_containers(self) -> List[Dict]:
        """Get all LXC containers"""
        containers = []

        for node in self.data['nodes']:
            node_name = node['name']
            result = self._api_get(f"nodes/{node_name}/lxc")

            if result:
                for ct in result:
                    ct_info = {
                        'vmid': ct['vmid'],
                        'name': ct.get('name', f"CT-{ct['vmid']}"),
                        'node': node_name,
                        'status': ct['status'],
                        'cpu': ct.get('cpus', 1),
                        'mem_mb': ct.get('maxmem', 0) // 1024 // 1024,
                        'disk_gb': ct.get('maxdisk', 0) // 1024 // 1024 // 1024,
                        'uptime': ct.get('uptime', 0),
                        'template': ct.get('template', 0) == 1,
                        'type': 'lxc'
                    }

                    # Get detailed config
                    config = self._api_get(f"nodes/{node_name}/lxc/{ct['vmid']}/config")
                    if config:
                        ct_info.update(self._parse_lxc_config(config))

                    containers.append(ct_info)

        self.data['containers'] = containers
        return containers

    def _parse_vm_config(self, config: Dict) -> Dict:
        """Parse QEMU VM configuration"""
        parsed = {
            'ostype': config.get('ostype', ''),
            'boot': config.get('boot', ''),
            'scsihw': config.get('scsihw', ''),
            'machine': config.get('machine', ''),
            'bios': config.get('bios', 'seabios'),
            'cores': config.get('cores', 1),
            'sockets': config.get('sockets', 1),
            'memory': config.get('memory', 0),
            'balloon': config.get('balloon', 0),
            'disks': [],
            'networks': []
        }

        # Parse disks (scsi0, ide0, virtio0, etc.)
        for key, value in config.items():
            if any(key.startswith(prefix) for prefix in ['scsi', 'ide', 'virtio', 'sata']):
                if isinstance(value, str) and ':' in value:
                    parsed['disks'].append({
                        'id': key,
                        'config': value
                    })

            # Parse network interfaces
            if key.startswith('net'):
                parsed['networks'].append({
                    'id': key,
                    'config': value
                })

        return parsed

    def _parse_lxc_config(self, config: Dict) -> Dict:
        """Parse LXC container configuration"""
        parsed = {
            'ostype': config.get('ostype', ''),
            'arch': config.get('arch', 'amd64'),
            'hostname': config.get('hostname', ''),
            'cores': config.get('cores', 1),
            'memory': config.get('memory', 512),
            'swap': config.get('swap', 512),
            'rootfs': config.get('rootfs', ''),
            'unprivileged': config.get('unprivileged', 0) == 1,
            'networks': [],
            'mounts': []
        }

        # Parse network interfaces
        for key, value in config.items():
            if key.startswith('net'):
                parsed['networks'].append({
                    'id': key,
                    'config': value
                })
            if key.startswith('mp'):
                parsed['mounts'].append({
                    'id': key,
                    'config': value
                })

        return parsed

    def _get_storage(self) -> List[Dict]:
        """Get storage information"""
        storage = []

        for node in self.data['nodes']:
            node_name = node['name']
            result = self._api_get(f"nodes/{node_name}/storage")

            if result:
                for store in result:
                    storage.append({
                        'name': store['storage'],
                        'node': node_name,
                        'type': store.get('type', ''),
                        'content': store.get('content', ''),
                        'total': store.get('total', 0),
                        'used': store.get('used', 0),
                        'avail': store.get('avail', 0),
                        'active': store.get('active', 1) == 1
                    })

        self.data['storage'] = storage
        return storage

    def _get_networks(self) -> List[Dict]:
        """Get network information"""
        networks = []

        for node in self.data['nodes']:
            node_name = node['name']
            result = self._api_get(f"nodes/{node_name}/network")

            if result:
                for net in result:
                    networks.append({
                        'iface': net['iface'],
                        'node': node_name,
                        'type': net.get('type', ''),
                        'address': net.get('address', ''),
                        'netmask': net.get('netmask', ''),
                        'gateway': net.get('gateway', ''),
                        'bridge_ports': net.get('bridge_ports', ''),
                        'active': net.get('active', 1) == 1
                    })

        self.data['networks'] = networks
        return networks

    def find_vm_by_name(self, name: str) -> Optional[Dict]:
        """Find a VM by name"""
        for vm in self.data['vms'] + self.data['containers']:
            if vm['name'].lower() == name.lower():
                return vm
        return None

    def find_vm_by_id(self, vmid: int) -> Optional[Dict]:
        """Find a VM by VMID"""
        for vm in self.data['vms'] + self.data['containers']:
            if vm['vmid'] == vmid:
                return vm
        return None

    def get_vm_specs_for_terraform(self, vm_name: str) -> Dict:
        """Get VM specs formatted for Terraform"""
        vm = self.find_vm_by_name(vm_name)
        if not vm:
            return {}

        return {
            'name': vm['name'],
            'vmid': vm['vmid'],
            'node': vm['node'],
            'type': vm['type'],
            'cores': vm.get('cores', 1),
            'sockets': vm.get('sockets', 1),
            'memory': vm.get('memory', vm.get('mem_mb', 512)),
            'disks': vm.get('disks', []),
            'networks': vm.get('networks', []),
            'ostype': vm.get('ostype', '')
        }
