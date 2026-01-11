"""
vCenter Connector
Connects to VMware vCenter to get VM information
"""

import logging
import ssl
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    PYVMOMI_AVAILABLE = True
except ImportError:
    PYVMOMI_AVAILABLE = False
    logger.warning("pyVmomi not available, vCenter features disabled")


class VCenterConnector:
    """Connects to VMware vCenter API"""

    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.connection = None
        self.data = {
            'vms': [],
            'hosts': [],
            'datastores': [],
            'networks': [],
            'clusters': [],
            'current_vm': {}
        }

    def connect(self) -> bool:
        """Establish connection to vCenter"""
        if not PYVMOMI_AVAILABLE:
            logger.error("pyVmomi library required for vCenter connection")
            return False

        try:
            # Disable SSL verification (for self-signed certs)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            self.connection = SmartConnect(
                host=self.host,
                user=self.username,
                pwd=self.password,
                port=self.port,
                sslContext=context
            )
            logger.info(f"Connected to vCenter: {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to vCenter: {e}")
            return False

    def disconnect(self):
        """Disconnect from vCenter"""
        if self.connection:
            try:
                Disconnect(self.connection)
            except Exception:
                pass

    def get_vm_info(self) -> Dict[str, Any]:
        """Get comprehensive VM information"""
        if not self.connect():
            return {}

        try:
            self._get_all_vms()
            self._get_hosts()
            self._get_datastores()
            self._get_networks()
            self._get_clusters()
        except Exception as e:
            logger.error(f"Error getting VM info: {e}")
        finally:
            self.disconnect()

        return self.data

    def _get_all_vms(self) -> List[Dict]:
        """Get all virtual machines"""
        vms = []

        content = self.connection.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.VirtualMachine],
            True
        )

        for vm in container.view:
            try:
                vm_info = self._extract_vm_info(vm)
                vms.append(vm_info)
            except Exception as e:
                logger.debug(f"Error getting info for VM: {e}")

        container.Destroy()
        self.data['vms'] = vms
        return vms

    def _extract_vm_info(self, vm) -> Dict:
        """Extract detailed information from a VM object"""
        config = vm.config
        summary = vm.summary
        runtime = vm.runtime

        vm_info = {
            'name': vm.name,
            'uuid': config.uuid if config else '',
            'instance_uuid': config.instanceUuid if config else '',
            'power_state': str(runtime.powerState) if runtime else '',
            'guest_os': config.guestFullName if config else '',
            'guest_id': config.guestId if config else '',
            'num_cpu': config.hardware.numCPU if config and config.hardware else 0,
            'memory_mb': config.hardware.memoryMB if config and config.hardware else 0,
            'num_disks': 0,
            'total_disk_gb': 0,
            'disks': [],
            'networks': [],
            'ip_addresses': [],
            'hostname': '',
            'tools_status': '',
            'tools_version': '',
            'annotation': config.annotation if config else '',
            'folder': '',
            'resource_pool': '',
            'host': '',
            'datastore': []
        }

        # Get disk information
        if config and config.hardware:
            for device in config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualDisk):
                    disk_size_gb = device.capacityInKB / 1024 / 1024
                    vm_info['disks'].append({
                        'label': device.deviceInfo.label,
                        'size_gb': round(disk_size_gb, 2),
                        'thin_provisioned': getattr(device.backing, 'thinProvisioned', False)
                    })
                    vm_info['total_disk_gb'] += disk_size_gb
                    vm_info['num_disks'] += 1
                elif isinstance(device, vim.vm.device.VirtualEthernetCard):
                    vm_info['networks'].append({
                        'label': device.deviceInfo.label,
                        'mac_address': device.macAddress,
                        'connected': device.connectable.connected if device.connectable else False
                    })

        # Get guest information
        if vm.guest:
            vm_info['hostname'] = vm.guest.hostName or ''
            vm_info['tools_status'] = str(vm.guest.toolsStatus) if vm.guest.toolsStatus else ''
            vm_info['tools_version'] = vm.guest.toolsVersion or ''

            if vm.guest.net:
                for nic in vm.guest.net:
                    if nic.ipAddress:
                        vm_info['ip_addresses'].extend(nic.ipAddress)

        # Get location information
        if vm.parent:
            vm_info['folder'] = vm.parent.name
        if vm.resourcePool:
            vm_info['resource_pool'] = vm.resourcePool.name
        if runtime and runtime.host:
            vm_info['host'] = runtime.host.name

        # Get datastores
        if vm.datastore:
            vm_info['datastore'] = [ds.name for ds in vm.datastore]

        vm_info['total_disk_gb'] = round(vm_info['total_disk_gb'], 2)
        return vm_info

    def _get_hosts(self) -> List[Dict]:
        """Get ESXi host information"""
        hosts = []

        content = self.connection.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.HostSystem],
            True
        )

        for host in container.view:
            try:
                hosts.append({
                    'name': host.name,
                    'connection_state': str(host.runtime.connectionState),
                    'power_state': str(host.runtime.powerState),
                    'cpu_cores': host.hardware.cpuInfo.numCpuCores if host.hardware else 0,
                    'memory_gb': round(host.hardware.memorySize / 1024 / 1024 / 1024, 2) if host.hardware else 0,
                    'version': host.config.product.version if host.config else '',
                    'build': host.config.product.build if host.config else ''
                })
            except Exception as e:
                logger.debug(f"Error getting host info: {e}")

        container.Destroy()
        self.data['hosts'] = hosts
        return hosts

    def _get_datastores(self) -> List[Dict]:
        """Get datastore information"""
        datastores = []

        content = self.connection.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.Datastore],
            True
        )

        for ds in container.view:
            try:
                summary = ds.summary
                datastores.append({
                    'name': ds.name,
                    'type': summary.type,
                    'capacity_gb': round(summary.capacity / 1024 / 1024 / 1024, 2),
                    'free_gb': round(summary.freeSpace / 1024 / 1024 / 1024, 2),
                    'accessible': summary.accessible
                })
            except Exception as e:
                logger.debug(f"Error getting datastore info: {e}")

        container.Destroy()
        self.data['datastores'] = datastores
        return datastores

    def _get_networks(self) -> List[Dict]:
        """Get network information"""
        networks = []

        content = self.connection.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.Network],
            True
        )

        for network in container.view:
            try:
                networks.append({
                    'name': network.name,
                    'type': type(network).__name__,
                    'accessible': network.summary.accessible if hasattr(network.summary, 'accessible') else True
                })
            except Exception as e:
                logger.debug(f"Error getting network info: {e}")

        container.Destroy()
        self.data['networks'] = networks
        return networks

    def _get_clusters(self) -> List[Dict]:
        """Get cluster information"""
        clusters = []

        content = self.connection.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.ClusterComputeResource],
            True
        )

        for cluster in container.view:
            try:
                clusters.append({
                    'name': cluster.name,
                    'num_hosts': len(cluster.host) if cluster.host else 0,
                    'total_cpu': cluster.summary.totalCpu if cluster.summary else 0,
                    'total_memory_gb': round(cluster.summary.totalMemory / 1024 / 1024 / 1024, 2) if cluster.summary else 0,
                    'drs_enabled': cluster.configuration.drsConfig.enabled if cluster.configuration else False,
                    'ha_enabled': cluster.configuration.dasConfig.enabled if cluster.configuration else False
                })
            except Exception as e:
                logger.debug(f"Error getting cluster info: {e}")

        container.Destroy()
        self.data['clusters'] = clusters
        return clusters

    def find_vm_by_name(self, name: str) -> Optional[Dict]:
        """Find a specific VM by name"""
        for vm in self.data['vms']:
            if vm['name'].lower() == name.lower():
                return vm
        return None

    def find_vm_by_ip(self, ip: str) -> Optional[Dict]:
        """Find a VM by IP address"""
        for vm in self.data['vms']:
            if ip in vm.get('ip_addresses', []):
                return vm
        return None

    def get_vm_specs_for_terraform(self, vm_name: str) -> Dict:
        """Get VM specs formatted for Terraform"""
        vm = self.find_vm_by_name(vm_name)
        if not vm:
            return {}

        return {
            'name': vm['name'],
            'num_cpus': vm['num_cpu'],
            'memory': vm['memory_mb'],
            'guest_id': vm['guest_id'],
            'disks': vm['disks'],
            'networks': vm['networks'],
            'datastore': vm['datastore'][0] if vm['datastore'] else '',
            'folder': vm['folder'],
            'resource_pool': vm['resource_pool']
        }
