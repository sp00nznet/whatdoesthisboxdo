#!/usr/bin/env python3
"""
System Analyzer Tool
Analyzes existing systems and generates documentation and Infrastructure-as-Code
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from analyzers.process_analyzer import ProcessAnalyzer
from analyzers.file_analyzer import FileAnalyzer
from analyzers.history_analyzer import HistoryAnalyzer
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

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'processes': {},
            'files': {},
            'history': {},
            'gitlab': {},
            'harbor': {},
            'virtualization': {},
            'summary': {}
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
        """Scan GitLab repositories"""
        logger.info("Scanning GitLab repositories...")
        if not self.config['gitlab']['url']:
            logger.warning("GitLab URL not configured, skipping...")
            return {}
        connector = GitLabConnector(
            self.config['gitlab']['url'],
            self.config['gitlab']['token']
        )
        self.analysis_data['gitlab'] = connector.scan_repos()
        return self.analysis_data['gitlab']

    def analyze_harbor(self) -> dict:
        """Scan Harbor container registry"""
        logger.info("Scanning Harbor registry...")
        if not self.config['harbor']['url']:
            logger.warning("Harbor URL not configured, skipping...")
            return {}
        connector = HarborConnector(
            self.config['harbor']['url'],
            self.config['harbor']['username'],
            self.config['harbor']['password']
        )
        self.analysis_data['harbor'] = connector.scan_registry()
        return self.analysis_data['harbor']

    def analyze_virtualization(self) -> dict:
        """Analyze virtualization platform (vCenter or Proxmox)"""
        logger.info("Analyzing virtualization platform...")

        if self.config['vcenter']['host']:
            connector = VCenterConnector(
                self.config['vcenter']['host'],
                self.config['vcenter']['username'],
                self.config['vcenter']['password']
            )
            self.analysis_data['virtualization'] = {
                'platform': 'vcenter',
                'data': connector.get_vm_info()
            }
        elif self.config['proxmox']['host']:
            connector = ProxmoxConnector(
                self.config['proxmox']['host'],
                self.config['proxmox']['username'],
                self.config['proxmox']['password']
            )
            self.analysis_data['virtualization'] = {
                'platform': 'proxmox',
                'data': connector.get_vm_info()
            }
        else:
            logger.warning("No virtualization platform configured, skipping...")

        return self.analysis_data['virtualization']

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

    def run_full_analysis(self) -> dict:
        """Run complete system analysis"""
        logger.info("Starting full system analysis...")

        self.analyze_processes()
        self.analyze_files()
        self.analyze_history()
        self.analyze_gitlab()
        self.analyze_harbor()
        self.analyze_virtualization()
        self.generate_summary()

        logger.info("Analysis complete!")
        return self.analysis_data

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
        description='System Analyzer - Analyze systems and generate documentation/IaC'
    )
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
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    analyzer = SystemAnalyzer(args.config)
    analyzer.config['output_dir'] = args.output

    if args.generate_only:
        if args.analysis_file:
            with open(args.analysis_file, 'r') as f:
                analyzer.analysis_data = json.load(f)
        else:
            print("Error: --analysis-file required with --generate-only")
            sys.exit(1)
    else:
        analyzer.run_full_analysis()
        analyzer.save_analysis()

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
