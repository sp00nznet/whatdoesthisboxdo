#!/usr/bin/env python3
"""
System Analyzer Tool
Analyzes existing systems and generates documentation and Infrastructure-as-Code
Supports both local and remote (SSH) analysis
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Load .env file if present
def load_dotenv():
    """Load environment variables from .env file"""
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ.setdefault(key.strip(), value.strip())

load_dotenv()

from analyzers.process_analyzer import ProcessAnalyzer
from analyzers.file_analyzer import FileAnalyzer
from analyzers.history_analyzer import HistoryAnalyzer
from analyzers.remote_analyzer import RemoteSystemAnalyzer
from analyzers.metrics_monitor import MetricsMonitor
from connectors.ssh_executor import SSHExecutor, SSHConfig
from connectors.local_executor import LocalExecutor, LocalConfig

# Optional Windows support
try:
    from connectors.winrm_executor import WinRMExecutor, WinRMConfig
    from analyzers.windows_analyzer import WindowsSystemAnalyzer
    WINDOWS_SUPPORT = True
except ImportError:
    WINDOWS_SUPPORT = False
from connectors.gitlab_connector import GitLabConnector
from connectors.harbor_connector import HarborConnector
from connectors.vcenter_connector import VCenterConnector
from connectors.proxmox_connector import ProxmoxConnector
from generators.doc_generator import DocumentationGenerator
from generators.terraform_generator import TerraformGenerator
from generators.ansible_generator import AnsibleGenerator
from generators.packer_generator import PackerGenerator
from generators.aws_generator import AWSGenerator
from generators.gcp_generator import GCPGenerator
from generators.azure_generator import AzureGenerator
from generators.cost_estimator import CostEstimator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SystemAnalyzer:
    """Main system analyzer class that orchestrates all analysis and generation"""

    def __init__(self, config_path: str = None, remote_config: SSHConfig = None,
                 winrm_config=None, local_mode: bool = False, monitor_duration: int = 0):
        self.config = self._load_config(config_path)
        self.remote_config = remote_config
        self.winrm_config = winrm_config
        self.local_mode = local_mode
        self.ssh: SSHExecutor = None
        self.winrm = None
        self.local_executor = None
        self.is_remote = remote_config is not None or winrm_config is not None
        self.is_windows = winrm_config is not None
        self.monitor_duration = monitor_duration  # Duration in seconds for metrics collection
        self.analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'processes': {},
            'files': {},
            'history': {},
            'gitlab': {},
            'harbor': {},
            'virtualization': {},
            'summary': {},
            'metrics_analysis': {},
            'monitoring_duration': monitor_duration,
            'external_sources': {
                'gitlab': {'configured': False, 'connected': False, 'error': None, 'data_collected': False},
                'harbor': {'configured': False, 'connected': False, 'error': None, 'data_collected': False},
                'vcenter': {'configured': False, 'connected': False, 'error': None, 'data_collected': False},
                'proxmox': {'configured': False, 'connected': False, 'error': None, 'data_collected': False}
            },
            'path_repo_matches': [],  # Paths matched to GitLab repos
            'container_registry_matches': []  # Running containers matched to Harbor
        }

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'gitlab': {
                'url': os.getenv('GITLAB_URL', ''),
                'token': os.getenv('GITLAB_TOKEN', '')
            },
            'harbor': {
                'url': os.getenv('HARBOR_URL', ''),
                'username': os.getenv('HARBOR_USERNAME', ''),
                'password': os.getenv('HARBOR_PASSWORD', '')
            },
            'vcenter': {
                'host': os.getenv('VCENTER_HOST', ''),
                'username': os.getenv('VCENTER_USERNAME', ''),
                'password': os.getenv('VCENTER_PASSWORD', '')
            },
            'proxmox': {
                'host': os.getenv('PROXMOX_HOST', ''),
                'username': os.getenv('PROXMOX_USERNAME', ''),
                'password': os.getenv('PROXMOX_PASSWORD', '')
            },
            'output_dir': 'output',
            'analyze_users': [],  # Users whose history to analyze
            'vsphere_template': 'ubuntu-22.04-template'
        }

        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                # Merge configs
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value

        return default_config

    def analyze_processes(self) -> dict:
        """Analyze running processes"""
        logger.info("Analyzing running processes...")
        analyzer = ProcessAnalyzer()
        self.analysis_data['processes'] = analyzer.analyze()
        return self.analysis_data['processes']

    def analyze_files(self, paths: list = None) -> dict:
        """Analyze files being processed"""
        logger.info("Analyzing files...")
        analyzer = FileAnalyzer()
        self.analysis_data['files'] = analyzer.analyze(paths)
        return self.analysis_data['files']

    def analyze_history(self) -> dict:
        """Analyze bash histories"""
        logger.info("Analyzing bash histories...")
        analyzer = HistoryAnalyzer(self.config.get('analyze_users', []))
        self.analysis_data['history'] = analyzer.analyze()
        return self.analysis_data['history']

    def analyze_gitlab(self) -> dict:
        """Scan GitLab repositories and match with server paths"""
        logger.info("Scanning GitLab repositories...")
        ext = self.analysis_data['external_sources']['gitlab']

        if not self.config['gitlab']['url'] or not self.config['gitlab']['token']:
            ext['error'] = 'GitLab URL or token not configured in .env'
            logger.warning("GitLab not configured - set GITLAB_URL and GITLAB_TOKEN in .env")
            return {}

        ext['configured'] = True

        try:
            connector = GitLabConnector(
                self.config['gitlab']['url'],
                self.config['gitlab']['token']
            )
            self.analysis_data['gitlab'] = connector.scan_repos()
            ext['connected'] = True

            if self.analysis_data['gitlab'].get('projects'):
                ext['data_collected'] = True
                # Match server paths with GitLab repos
                self._match_paths_to_repos(connector)

        except Exception as e:
            ext['error'] = str(e)
            logger.error(f"GitLab connection failed: {e}")

        return self.analysis_data['gitlab']

    def _match_paths_to_repos(self, gitlab: GitLabConnector):
        """Match paths found on server with GitLab repositories"""
        matches = []

        # Get important paths from file analysis
        important_paths = self.analysis_data.get('files', {}).get('important_paths', [])
        service_configs = self.analysis_data.get('files', {}).get('service_configs', {})

        # Also check /opt, /var/www, /srv, /home directories
        check_paths = ['/opt', '/var/www', '/srv', '/home']
        hostname = self.analysis_data.get('hostname', '')

        # Search for hostname and path names in GitLab
        for project in self.analysis_data['gitlab'].get('projects', []):
            project_name = project.get('name', '').lower()
            project_path = project.get('path', '').lower()
            description = project.get('description', '').lower() if project.get('description') else ''

            # Check if hostname matches
            if hostname.lower() in description or hostname.lower() in project_name:
                matches.append({
                    'type': 'hostname_match',
                    'project': project['path'],
                    'url': project.get('web_url', ''),
                    'match_reason': f"Project references hostname '{hostname}'"
                })

        # Search code for hostname
        related = gitlab.find_related_projects(hostname)
        for item in related[:10]:
            if isinstance(item, dict) and 'project' in item:
                matches.append({
                    'type': 'code_reference',
                    'project': item.get('project'),
                    'path': item.get('path', ''),
                    'match_reason': f"Code contains reference to '{hostname}'"
                })

        self.analysis_data['path_repo_matches'] = matches

    def analyze_harbor(self) -> dict:
        """Scan Harbor container registry and match with running containers"""
        logger.info("Scanning Harbor registry...")
        ext = self.analysis_data['external_sources']['harbor']

        if not self.config['harbor']['url']:
            ext['error'] = 'Harbor URL not configured in .env'
            logger.warning("Harbor not configured - set HARBOR_URL, HARBOR_USERNAME, HARBOR_PASSWORD in .env")
            return {}

        ext['configured'] = True

        try:
            connector = HarborConnector(
                self.config['harbor']['url'],
                self.config['harbor']['username'],
                self.config['harbor']['password']
            )
            self.analysis_data['harbor'] = connector.scan_registry()
            ext['connected'] = True

            if self.analysis_data['harbor'].get('repositories'):
                ext['data_collected'] = True
                # Match running containers with Harbor images
                self._match_containers_to_registry(connector)

        except Exception as e:
            ext['error'] = str(e)
            logger.error(f"Harbor connection failed: {e}")

        return self.analysis_data['harbor']

    def _match_containers_to_registry(self, harbor: HarborConnector):
        """Match running Docker containers with Harbor registry images"""
        matches = []

        # Get running Docker containers from process analysis
        processes = self.analysis_data.get('processes', {}).get('running', [])
        docker_processes = [p for p in processes if 'docker' in p.get('cmdline', '').lower()
                           or 'containerd' in p.get('name', '').lower()]

        # Check if we found docker info in history
        history_cmds = self.analysis_data.get('history', {}).get('commands', [])
        docker_cmds = [c for c in history_cmds if 'docker' in c.get('command', '').lower()]

        # Extract image names from docker commands
        image_names = set()
        for cmd in docker_cmds:
            cmd_str = cmd.get('command', '')
            # Look for docker run/pull commands
            if 'docker run' in cmd_str or 'docker pull' in cmd_str:
                # Extract image name (simplified parsing)
                parts = cmd_str.split()
                for i, part in enumerate(parts):
                    if part in ['run', 'pull'] and i + 1 < len(parts):
                        img = parts[i + 1]
                        if not img.startswith('-'):
                            image_names.add(img.split(':')[0])  # Remove tag

        # Match with Harbor artifacts
        for artifact in self.analysis_data['harbor'].get('artifacts', []):
            repo_name = artifact.get('repository', '')
            for img_name in image_names:
                if img_name in repo_name or repo_name.endswith(img_name):
                    matches.append({
                        'type': 'container_image_match',
                        'local_image': img_name,
                        'harbor_repo': repo_name,
                        'tags': artifact.get('tags', []),
                        'vulnerabilities': artifact.get('vulnerabilities', {}),
                        'match_reason': f"Running container '{img_name}' found in Harbor"
                    })

        # Also check for hostname-related images
        hostname = self.analysis_data.get('hostname', '')
        related_images = harbor.find_images_for_hostname(hostname)
        for img in related_images:
            matches.append({
                'type': 'hostname_related_image',
                'harbor_repo': img.get('repository', ''),
                'tags': img.get('tags', []),
                'match_reason': f"Harbor image references hostname '{hostname}'"
            })

        self.analysis_data['container_registry_matches'] = matches

    def analyze_virtualization(self) -> dict:
        """Analyze virtualization platform (vCenter or Proxmox)"""
        logger.info("Analyzing virtualization platform...")
        hostname = self.analysis_data.get('hostname', '')

        # Try vCenter
        if self.config['vcenter']['host']:
            ext = self.analysis_data['external_sources']['vcenter']
            ext['configured'] = True

            try:
                connector = VCenterConnector(
                    self.config['vcenter']['host'],
                    self.config['vcenter']['username'],
                    self.config['vcenter']['password']
                )
                vm_data = connector.get_vm_info()
                ext['connected'] = True

                if vm_data:
                    ext['data_collected'] = True
                    # Find this VM's info
                    vm_info = connector.find_vm_by_name(hostname) if hasattr(connector, 'find_vm_by_name') else None
                    self.analysis_data['virtualization'] = {
                        'platform': 'vcenter',
                        'data': vm_data,
                        'this_vm': vm_info
                    }
            except Exception as e:
                ext['error'] = str(e)
                logger.error(f"vCenter connection failed: {e}")

        # Try Proxmox
        elif self.config['proxmox']['host']:
            ext = self.analysis_data['external_sources']['proxmox']
            ext['configured'] = True

            try:
                connector = ProxmoxConnector(
                    self.config['proxmox']['host'],
                    self.config['proxmox']['username'],
                    self.config['proxmox']['password']
                )
                vm_data = connector.get_vm_info()
                ext['connected'] = True

                if vm_data:
                    ext['data_collected'] = True
                    # Find this VM's info
                    vm_info = connector.find_vm_by_name(hostname) if hasattr(connector, 'find_vm_by_name') else None
                    self.analysis_data['virtualization'] = {
                        'platform': 'proxmox',
                        'data': vm_data,
                        'this_vm': vm_info
                    }
            except Exception as e:
                ext['error'] = str(e)
                logger.error(f"Proxmox connection failed: {e}")
        else:
            self.analysis_data['external_sources']['vcenter']['error'] = 'Not configured in .env'
            self.analysis_data['external_sources']['proxmox']['error'] = 'Not configured in .env'
            logger.warning("No virtualization platform configured - set VCENTER_* or PROXMOX_* in .env")

        return self.analysis_data.get('virtualization', {})

    def generate_summary(self) -> dict:
        """Generate a summary of the system analysis"""
        logger.info("Generating analysis summary...")

        summary = {
            'server_purpose': self._infer_server_purpose(),
            'key_services': self._identify_key_services(),
            'installed_applications': self._list_applications(),
            'data_flows': self._identify_data_flows(),
            'dependencies': self._identify_dependencies(),
            'potential_issues': self._identify_potential_issues()
        }

        self.analysis_data['summary'] = summary
        return summary

    def _infer_server_purpose(self) -> str:
        """Infer the primary purpose of the server based on analysis"""
        purposes = []
        processes = self.analysis_data.get('processes', {})

        # Check for common server types
        service_indicators = {
            'web_server': ['nginx', 'apache', 'httpd', 'caddy'],
            'database': ['mysql', 'postgres', 'mongodb', 'redis', 'mariadb'],
            'container_host': ['docker', 'containerd', 'podman'],
            'kubernetes': ['kubelet', 'kube-proxy', 'etcd'],
            'ci_cd': ['jenkins', 'gitlab-runner', 'drone'],
            'monitoring': ['prometheus', 'grafana', 'zabbix', 'nagios'],
            'mail_server': ['postfix', 'dovecot', 'sendmail'],
            'file_server': ['smbd', 'nfsd', 'vsftpd'],
            'load_balancer': ['haproxy', 'traefik', 'envoy'],
            'message_queue': ['rabbitmq', 'kafka', 'activemq']
        }

        running_procs = [p.get('name', '').lower() for p in processes.get('running', [])]

        for purpose, indicators in service_indicators.items():
            if any(ind in ' '.join(running_procs) for ind in indicators):
                purposes.append(purpose)

        return ', '.join(purposes) if purposes else 'General purpose server'

    def _identify_key_services(self) -> list:
        """Identify key services running on the system"""
        services = []
        processes = self.analysis_data.get('processes', {})

        for proc in processes.get('services', []):
            services.append({
                'name': proc.get('name'),
                'status': proc.get('status'),
                'ports': proc.get('ports', [])
            })

        return services

    def _list_applications(self) -> list:
        """List installed applications"""
        apps = []
        processes = self.analysis_data.get('processes', {})

        for proc in processes.get('running', []):
            if proc.get('name') not in [a.get('name') for a in apps]:
                apps.append({
                    'name': proc.get('name'),
                    'path': proc.get('exe'),
                    'user': proc.get('user')
                })

        return apps

    def _identify_data_flows(self) -> list:
        """Identify data flows based on open connections"""
        flows = []
        processes = self.analysis_data.get('processes', {})

        for conn in processes.get('connections', []):
            flows.append({
                'process': conn.get('process'),
                'local': f"{conn.get('local_addr')}:{conn.get('local_port')}",
                'remote': f"{conn.get('remote_addr')}:{conn.get('remote_port')}",
                'status': conn.get('status')
            })

        return flows

    def _identify_dependencies(self) -> list:
        """Identify system dependencies"""
        deps = []
        history = self.analysis_data.get('history', {})

        # Check for package installations in history
        for cmd in history.get('commands', []):
            if any(pm in cmd for pm in ['apt install', 'yum install', 'dnf install', 'pip install']):
                deps.append(cmd)

        return deps

    def _identify_potential_issues(self) -> list:
        """Identify potential issues and troubleshooting areas"""
        issues = []
        processes = self.analysis_data.get('processes', {})

        # Check for high resource usage
        for proc in processes.get('running', []):
            if proc.get('cpu_percent', 0) > 80:
                issues.append(f"High CPU usage: {proc.get('name')} ({proc.get('cpu_percent')}%)")
            if proc.get('memory_percent', 0) > 80:
                issues.append(f"High memory usage: {proc.get('name')} ({proc.get('memory_percent')}%)")

        return issues

    def connect_remote(self) -> bool:
        """Connect to remote server via SSH"""
        if not self.remote_config:
            return False

        self.ssh = SSHExecutor(self.remote_config)
        if self.ssh.connect():
            self.analysis_data['hostname'] = self.ssh.get_hostname()
            self.analysis_data['os_info'] = self.ssh.get_os_info()
            return True
        return False

    def disconnect_remote(self) -> None:
        """Disconnect from remote server"""
        if self.ssh:
            self.ssh.disconnect()
            self.ssh = None

    def run_remote_analysis(self) -> dict:
        """Run analysis on a remote server via SSH"""
        if not self.ssh or not self.ssh.connected:
            if not self.connect_remote():
                raise RuntimeError(f"Failed to connect to {self.remote_config.hostname}")

        logger.info(f"Starting remote analysis of {self.analysis_data['hostname']}...")

        try:
            # Run metrics monitoring if duration is set
            if self.monitor_duration > 0:
                logger.info(f"Starting metrics collection for {self.monitor_duration} seconds...")
                monitor = MetricsMonitor(self.ssh)

                # Determine interval based on duration
                if self.monitor_duration <= 30:
                    interval = 3
                elif self.monitor_duration <= 120:
                    interval = 5
                else:
                    interval = 10

                monitor.monitor(self.monitor_duration, interval)
                self.analysis_data['metrics_analysis'] = monitor.get_analysis()
                self.analysis_data['monitoring_duration'] = self.monitor_duration
                logger.info("Metrics collection complete!")

            analyzer = RemoteSystemAnalyzer(self.ssh)
            remote_data = analyzer.analyze_all()

            # Merge with analysis_data (but preserve metrics_analysis)
            metrics_backup = self.analysis_data.get('metrics_analysis', {})
            monitoring_duration = self.analysis_data.get('monitoring_duration', 0)
            self.analysis_data.update(remote_data)
            self.analysis_data['metrics_analysis'] = metrics_backup
            self.analysis_data['monitoring_duration'] = monitoring_duration
            self.analysis_data['timestamp'] = datetime.now().isoformat()

            # Generate summary
            self.generate_summary()

            logger.info("Remote analysis complete!")
            return self.analysis_data

        finally:
            self.disconnect_remote()

    def run_windows_analysis(self) -> dict:
        """Run analysis on a remote Windows server via WinRM"""
        if not WINDOWS_SUPPORT:
            raise RuntimeError(
                "Windows support requires pywinrm.\n"
                "Install with: pip3 install pywinrm"
            )

        if not self.winrm_config:
            raise RuntimeError("WinRM configuration not provided")

        self.winrm = WinRMExecutor(self.winrm_config)
        if not self.winrm.connect():
            raise RuntimeError(f"Failed to connect to {self.winrm_config.hostname}")

        logger.info(f"Starting Windows analysis of {self.winrm.get_hostname()}...")

        try:
            analyzer = WindowsSystemAnalyzer(self.winrm)
            remote_data = analyzer.analyze_all()

            self.analysis_data.update(remote_data)
            self.analysis_data['timestamp'] = datetime.now().isoformat()
            self.analysis_data['os_type'] = 'windows'

            # Run external source analysis
            self.analyze_gitlab()
            self.analyze_harbor()
            self.analyze_virtualization()

            # Generate summary
            self.generate_summary()

            logger.info("Windows analysis complete!")
            return self.analysis_data

        finally:
            self.winrm.disconnect()

    def run_local_analysis(self) -> dict:
        """Run analysis on the local system (no SSH/WinRM needed)"""
        import platform

        self.local_executor = LocalExecutor(LocalConfig(use_sudo=True))
        self.local_executor.connect()

        is_windows = platform.system() == 'Windows'
        self.analysis_data['hostname'] = self.local_executor.get_hostname()
        self.analysis_data['os_info'] = self.local_executor.get_os_info()
        self.analysis_data['os_type'] = 'windows' if is_windows else 'linux'

        logger.info(f"Starting local analysis of {self.analysis_data['hostname']}...")

        try:
            if is_windows:
                if not WINDOWS_SUPPORT:
                    raise RuntimeError(
                        "Windows local analysis requires the windows_analyzer module."
                    )
                # Use Windows analyzer with local executor
                analyzer = WindowsSystemAnalyzer(self.local_executor)
                remote_data = analyzer.analyze_all()
            else:
                # Use Linux analyzer with local executor
                analyzer = RemoteSystemAnalyzer(self.local_executor)
                remote_data = analyzer.analyze_all()

            # Run metrics monitoring if duration is set
            if self.monitor_duration > 0 and not is_windows:
                logger.info(f"Starting metrics collection for {self.monitor_duration} seconds...")
                monitor = MetricsMonitor(self.local_executor)

                if self.monitor_duration <= 30:
                    interval = 3
                elif self.monitor_duration <= 120:
                    interval = 5
                else:
                    interval = 10

                monitor.monitor(self.monitor_duration, interval)
                self.analysis_data['metrics_analysis'] = monitor.get_analysis()
                self.analysis_data['monitoring_duration'] = self.monitor_duration
                logger.info("Metrics collection complete!")

            self.analysis_data.update(remote_data)
            self.analysis_data['timestamp'] = datetime.now().isoformat()

            # Run external source analysis
            self.analyze_gitlab()
            self.analyze_harbor()
            self.analyze_virtualization()

            # Generate summary
            self.generate_summary()

            logger.info("Local analysis complete!")
            return self.analysis_data

        finally:
            self.local_executor.disconnect()

    def run_full_analysis(self) -> dict:
        """Run complete system analysis (local, remote SSH, or remote WinRM)"""
        if self.local_mode:
            return self.run_local_analysis()

        if self.winrm_config:
            return self.run_windows_analysis()

        if self.is_remote:
            return self.run_remote_analysis()

        # Default to local analysis
        logger.info("No remote config provided, running local analysis...")
        self.local_mode = True
        return self.run_local_analysis()

    def generate_documentation(self, output_path: str = None) -> str:
        """Generate documentation from analysis"""
        logger.info("Generating documentation...")
        generator = DocumentationGenerator(self.analysis_data)
        return generator.generate(output_path or f"{self.config['output_dir']}/documentation.md")

    def generate_terraform(self, output_path: str = None) -> str:
        """Generate Terraform configuration"""
        logger.info("Generating Terraform configuration...")
        generator = TerraformGenerator(
            self.analysis_data,
            self.config.get('vsphere_template')
        )
        return generator.generate(output_path or f"{self.config['output_dir']}/terraform")

    def generate_ansible(self, output_path: str = None) -> str:
        """Generate Ansible playbooks"""
        logger.info("Generating Ansible playbooks...")
        generator = AnsibleGenerator(self.analysis_data)
        return generator.generate(output_path or f"{self.config['output_dir']}/ansible")

    def generate_packer(self, output_path: str = None) -> str:
        """Generate Packer templates"""
        logger.info("Generating Packer templates...")
        generator = PackerGenerator(
            self.analysis_data,
            self.config.get('vsphere_template')
        )
        return generator.generate(output_path or f"{self.config['output_dir']}/packer")

    def generate_aws(self, output_path: str = None) -> str:
        """Generate AWS Terraform configuration"""
        logger.info("Generating AWS Terraform configuration...")
        generator = AWSGenerator(self.analysis_data)
        return generator.generate(output_path or f"{self.config['output_dir']}/terraform-aws")

    def generate_gcp(self, output_path: str = None) -> str:
        """Generate GCP Terraform configuration"""
        logger.info("Generating GCP Terraform configuration...")
        generator = GCPGenerator(self.analysis_data)
        return generator.generate(output_path or f"{self.config['output_dir']}/terraform-gcp")

    def generate_azure(self, output_path: str = None) -> str:
        """Generate Azure Terraform configuration"""
        logger.info("Generating Azure Terraform configuration...")
        generator = AzureGenerator(self.analysis_data)
        return generator.generate(output_path or f"{self.config['output_dir']}/terraform-azure")

    def estimate_costs(self) -> dict:
        """Estimate cloud costs for all providers"""
        logger.info("Estimating cloud costs...")
        estimator = CostEstimator(self.analysis_data)
        return estimator.generate_report()

    def generate_cost_report(self, output_path: str = None) -> str:
        """Generate cost estimation report"""
        logger.info("Generating cost report...")
        cost_report = self.estimate_costs()

        path = output_path or f"{self.config['output_dir']}/cost-estimate.md"
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)

        with open(path, 'w') as f:
            f.write(f"# Cloud Cost Estimate: {self.analysis_data.get('hostname', 'Server')}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")

            f.write("## System Specifications\n\n")
            specs = cost_report.get('specs', {})
            f.write(f"| Resource | Value |\n")
            f.write(f"|----------|-------|\n")
            f.write(f"| vCPUs | {specs.get('vcpus', 'N/A')} |\n")
            f.write(f"| Memory | {specs.get('memory_gb', 'N/A')} GB |\n")
            f.write(f"| Storage | {specs.get('storage_gb', 'N/A')} GB |\n\n")

            f.write(cost_report.get('comparison', ''))

            f.write("\n\n---\n\n")
            f.write("## Detailed Estimates\n\n")

            for provider, estimate in cost_report.get('estimates', {}).items():
                f.write(f"### {estimate.get('provider', provider.upper())}\n\n")
                f.write(f"- **Instance Type:** {estimate.get('instance_type')}\n")
                f.write(f"- **Region:** {estimate.get('region')}\n")
                f.write(f"- **Hourly Cost:** ${estimate.get('hourly_cost', 0):.4f}\n")
                f.write(f"- **Monthly Cost:** ${estimate.get('monthly_cost', 0):,.2f}\n")
                f.write(f"- **Annual Cost:** ${estimate.get('annual_cost', 0):,.2f}\n\n")

                details = estimate.get('details', {})
                if details:
                    f.write("**Cost Breakdown:**\n")
                    for key, value in details.items():
                        if key != 'pricing_source':
                            f.write(f"- {key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")

            # Save JSON version too
            json_path = path.replace('.md', '.json')
            with open(json_path, 'w') as jf:
                json.dump(cost_report, jf, indent=2)

        logger.info(f"Cost report saved to {path}")
        return path

    def generate_all(self, include_cloud: bool = True) -> dict:
        """Generate all outputs"""
        outputs = {
            'documentation': self.generate_documentation(),
            'terraform_vsphere': self.generate_terraform(),
            'ansible': self.generate_ansible(),
            'packer': self.generate_packer()
        }

        if include_cloud:
            outputs['terraform_aws'] = self.generate_aws()
            outputs['terraform_gcp'] = self.generate_gcp()
            outputs['terraform_azure'] = self.generate_azure()
            outputs['cost_estimate'] = self.generate_cost_report()

        return outputs

    def save_analysis(self, output_path: str = None) -> str:
        """Save raw analysis data to JSON"""
        path = output_path or f"{self.config['output_dir']}/analysis.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.analysis_data, f, indent=2, default=str)

        logger.info(f"Analysis saved to {path}")
        return path


def main():
    parser = argparse.ArgumentParser(
        description='System Analyzer - Analyze systems and generate documentation/IaC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze the local system
  python3 analyzer.py --local

  # Analyze a remote Linux server (with SSH key)
  python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa

  # Analyze a remote Windows server (WinRM)
  python3 analyzer.py --windows -H winserver.example.com -u Administrator --password

  # Analyze with SSH password (no key)
  python3 analyzer.py -H server.example.com -u admin --password

  # Analyze with 60-second metrics monitoring
  python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa -m 60

  # Analyze with sudo password
  python3 analyzer.py -H server.example.com -u admin -k ~/.ssh/id_rsa --sudo-pass

  # Batch process from CSV
  python3 batch_processor.py servers.csv -k ~/.ssh/id_rsa
        """
    )

    # Analysis mode options
    mode_group = parser.add_argument_group('Analysis Mode')
    mode_group.add_argument(
        '--local',
        action='store_true',
        help='Analyze the local system (no remote connection)'
    )
    mode_group.add_argument(
        '--windows',
        action='store_true',
        help='Target is a Windows server (use WinRM instead of SSH)'
    )

    # Remote connection options
    remote_group = parser.add_argument_group('Remote Connection')
    remote_group.add_argument(
        '-H', '--host',
        help='Remote hostname or IP to analyze'
    )
    remote_group.add_argument(
        '-u', '--user',
        default='root',
        help='SSH/WinRM username (default: root)'
    )
    remote_group.add_argument(
        '-p', '--port',
        type=int,
        default=None,
        help='SSH port (default: 22) or WinRM port (default: 5985)'
    )
    remote_group.add_argument(
        '-k', '--key',
        help='Path to SSH private key'
    )
    remote_group.add_argument(
        '--sudo-pass',
        action='store_true',
        help='Prompt for sudo password (Linux only)'
    )
    remote_group.add_argument(
        '--password',
        action='store_true',
        help='Prompt for SSH/WinRM password'
    )
    remote_group.add_argument(
        '--winrm-ssl',
        action='store_true',
        help='Use HTTPS for WinRM connection (port 5986)'
    )

    # General options
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file',
        default='config.json'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output directory',
        default='output'
    )
    parser.add_argument(
        '--analyze-only',
        action='store_true',
        help='Only run analysis, skip generation'
    )
    parser.add_argument(
        '--generate-only',
        action='store_true',
        help='Skip analysis, only generate from existing data'
    )
    parser.add_argument(
        '--analysis-file',
        help='Path to existing analysis JSON file (for --generate-only)'
    )
    parser.add_argument(
        '--no-cloud',
        action='store_true',
        help='Skip cloud provider (AWS/GCP/Azure) generation'
    )
    parser.add_argument(
        '--cloud-only',
        action='store_true',
        help='Only generate cloud provider configs and cost estimates'
    )
    parser.add_argument(
        '--cost-only',
        action='store_true',
        help='Only generate cost estimates'
    )
    parser.add_argument(
        '-m', '--monitor',
        type=int,
        default=0,
        metavar='SECONDS',
        help='Collect metrics over specified duration (e.g., --monitor 60 for 1 minute)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build configuration based on mode
    remote_config = None
    winrm_config = None
    local_mode = args.local

    if args.host:
        import getpass

        password = None
        if args.password:
            password = getpass.getpass("Password: ")

        if args.windows:
            # Windows remote analysis via WinRM
            if not WINDOWS_SUPPORT:
                print("Error: Windows support requires pywinrm.")
                print("Install with: pip3 install pywinrm")
                sys.exit(1)

            winrm_port = args.port or (5986 if args.winrm_ssl else 5985)
            winrm_config = WinRMConfig(
                hostname=args.host,
                username=args.user,
                password=password or '',
                port=winrm_port,
                use_ssl=args.winrm_ssl
            )
        else:
            # Linux remote analysis via SSH
            sudo_password = None
            if args.sudo_pass:
                sudo_password = getpass.getpass("Sudo password: ")

            ssh_port = args.port or 22
            remote_config = SSHConfig(
                hostname=args.host,
                username=args.user,
                port=ssh_port,
                private_key_path=args.key,
                password=password,
                sudo_password=sudo_password,
                use_sudo=True
            )
    elif not args.local:
        # No host specified and not explicitly local - prompt user
        print("No host specified. Running local analysis...")
        print("Use --local to suppress this message, or -H <host> for remote analysis.")
        local_mode = True

    analyzer = SystemAnalyzer(
        args.config,
        remote_config=remote_config,
        winrm_config=winrm_config,
        local_mode=local_mode,
        monitor_duration=args.monitor
    )
    analyzer.config['output_dir'] = args.output

    # Adjust output directory for remote hosts or local
    if args.host:
        analyzer.config['output_dir'] = os.path.join(args.output, args.host)
    elif local_mode:
        import socket
        analyzer.config['output_dir'] = os.path.join(args.output, socket.gethostname())

    if args.generate_only:
        if args.analysis_file:
            with open(args.analysis_file, 'r') as f:
                analyzer.analysis_data = json.load(f)
        else:
            print("Error: --analysis-file required with --generate-only")
            sys.exit(1)
    else:
        try:
            analyzer.run_full_analysis()
            analyzer.save_analysis()
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            sys.exit(1)

    if not args.analyze_only:
        if args.cost_only:
            # Only generate cost estimates
            path = analyzer.generate_cost_report()
            print(f"\nCost estimate generated: {path}")
        elif args.cloud_only:
            # Only generate cloud configs
            outputs = {
                'terraform_aws': analyzer.generate_aws(),
                'terraform_gcp': analyzer.generate_gcp(),
                'terraform_azure': analyzer.generate_azure(),
                'cost_estimate': analyzer.generate_cost_report()
            }
            print("\nGenerated cloud outputs:")
            for name, path in outputs.items():
                print(f"  - {name}: {path}")
        else:
            # Generate all (with or without cloud)
            outputs = analyzer.generate_all(include_cloud=not args.no_cloud)
            print("\nGenerated outputs:")
            for name, path in outputs.items():
                print(f"  - {name}: {path}")

    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
