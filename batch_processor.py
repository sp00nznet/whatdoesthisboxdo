#!/usr/bin/env python3
"""
Batch Processor
Processes multiple servers from CSV input
"""

import argparse
import csv
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from connectors.ssh_executor import SSHExecutor, SSHConfig
from analyzers.remote_analyzer import RemoteSystemAnalyzer
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


@dataclass
class ServerEntry:
    """Server entry from CSV"""
    hostname: str
    username: str
    port: int = 22
    private_key: str = ""
    sudo_password: str = ""
    groups: str = ""
    notes: str = ""


class BatchProcessor:
    """Processes multiple servers from CSV input"""

    CSV_HEADERS = ['hostname', 'username', 'port', 'private_key', 'sudo_password', 'groups', 'notes']

    def __init__(self, output_dir: str = 'output', include_cloud: bool = True):
        self.output_dir = output_dir
        self.include_cloud = include_cloud
        self.results: Dict[str, Any] = {}
        self.errors: Dict[str, str] = {}

    def load_csv(self, csv_path: str) -> List[ServerEntry]:
        """Load server list from CSV file"""
        servers = []

        with open(csv_path, 'r', newline='') as f:
            # Try to detect the dialect
            sample = f.read(4096)
            f.seek(0)

            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel

            reader = csv.DictReader(f, dialect=dialect)

            for row in reader:
                # Skip empty rows
                if not row.get('hostname'):
                    continue

                server = ServerEntry(
                    hostname=row.get('hostname', '').strip(),
                    username=row.get('username', 'root').strip(),
                    port=int(row.get('port', 22)) if row.get('port', '').strip() else 22,
                    private_key=row.get('private_key', '').strip(),
                    sudo_password=row.get('sudo_password', '').strip(),
                    groups=row.get('groups', '').strip(),
                    notes=row.get('notes', '').strip()
                )
                servers.append(server)

        logger.info(f"Loaded {len(servers)} servers from {csv_path}")
        return servers

    def analyze_server(self, server: ServerEntry, default_key: str = None) -> Optional[Dict[str, Any]]:
        """Analyze a single server"""
        logger.info(f"Analyzing {server.hostname}...")

        # Determine private key
        key_path = server.private_key or default_key
        if key_path:
            key_path = os.path.expanduser(key_path)

        config = SSHConfig(
            hostname=server.hostname,
            username=server.username,
            port=server.port,
            private_key_path=key_path,
            sudo_password=server.sudo_password if server.sudo_password else None,
            use_sudo=True
        )

        try:
            ssh = SSHExecutor(config)
            if not ssh.connect():
                self.errors[server.hostname] = "Failed to connect"
                return None

            try:
                analyzer = RemoteSystemAnalyzer(ssh)
                data = analyzer.analyze_all()

                # Add metadata
                data['timestamp'] = datetime.now().isoformat()
                data['groups'] = server.groups
                data['notes'] = server.notes
                data['connection'] = {
                    'username': server.username,
                    'port': server.port
                }

                # Generate summary
                data['summary'] = self._generate_summary(data)

                return data

            finally:
                ssh.disconnect()

        except Exception as e:
            logger.error(f"Error analyzing {server.hostname}: {e}")
            self.errors[server.hostname] = str(e)
            return None

    def _generate_summary(self, data: Dict) -> Dict:
        """Generate analysis summary"""
        processes = data.get('processes', {})
        running = processes.get('running', [])

        # Infer server purpose
        purposes = []
        service_indicators = {
            'web_server': ['nginx', 'apache', 'httpd', 'caddy'],
            'database': ['mysql', 'postgres', 'mongodb', 'redis', 'mariadb'],
            'container_host': ['docker', 'containerd', 'podman'],
            'kubernetes': ['kubelet', 'kube-proxy', 'etcd'],
            'ci_cd': ['jenkins', 'gitlab-runner', 'drone'],
            'monitoring': ['prometheus', 'grafana', 'zabbix'],
        }

        running_names = [p.get('name', '').lower() for p in running]
        for purpose, indicators in service_indicators.items():
            if any(ind in ' '.join(running_names) for ind in indicators):
                purposes.append(purpose)

        # Key services
        services = processes.get('services', [])
        key_services = [
            {'name': s['name'], 'status': s['status']}
            for s in services if s.get('active') == 'active'
        ][:20]

        # Potential issues
        issues = []
        for proc in running:
            if proc.get('cpu_percent', 0) > 80:
                issues.append(f"High CPU: {proc.get('name')} ({proc.get('cpu_percent')}%)")
            if proc.get('memory_percent', 0) > 80:
                issues.append(f"High memory: {proc.get('name')} ({proc.get('memory_percent')}%)")

        return {
            'server_purpose': ', '.join(purposes) if purposes else 'General purpose server',
            'key_services': key_services,
            'potential_issues': issues,
            'process_count': len(running),
            'service_count': len(services)
        }

    def generate_outputs(self, hostname: str, data: Dict, server_output_dir: str) -> Dict[str, str]:
        """Generate all outputs for a server"""
        outputs = {}
        os.makedirs(server_output_dir, exist_ok=True)

        # Save raw analysis
        analysis_path = os.path.join(server_output_dir, 'analysis.json')
        with open(analysis_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        outputs['analysis'] = analysis_path

        # Documentation
        try:
            generator = DocumentationGenerator(data)
            outputs['documentation'] = generator.generate(
                os.path.join(server_output_dir, 'documentation.md')
            )
        except Exception as e:
            logger.warning(f"Could not generate documentation for {hostname}: {e}")

        # Ansible
        try:
            generator = AnsibleGenerator(data)
            outputs['ansible'] = generator.generate(
                os.path.join(server_output_dir, 'ansible')
            )
        except Exception as e:
            logger.warning(f"Could not generate Ansible for {hostname}: {e}")

        if self.include_cloud:
            # AWS
            try:
                generator = AWSGenerator(data)
                outputs['terraform_aws'] = generator.generate(
                    os.path.join(server_output_dir, 'terraform-aws')
                )
            except Exception as e:
                logger.warning(f"Could not generate AWS config for {hostname}: {e}")

            # GCP
            try:
                generator = GCPGenerator(data)
                outputs['terraform_gcp'] = generator.generate(
                    os.path.join(server_output_dir, 'terraform-gcp')
                )
            except Exception as e:
                logger.warning(f"Could not generate GCP config for {hostname}: {e}")

            # Azure
            try:
                generator = AzureGenerator(data)
                outputs['terraform_azure'] = generator.generate(
                    os.path.join(server_output_dir, 'terraform-azure')
                )
            except Exception as e:
                logger.warning(f"Could not generate Azure config for {hostname}: {e}")

            # Cost estimate
            try:
                estimator = CostEstimator(data)
                report = estimator.generate_report()

                cost_path = os.path.join(server_output_dir, 'cost-estimate.md')
                with open(cost_path, 'w') as f:
                    f.write(f"# Cost Estimate: {hostname}\n\n")
                    f.write(report.get('comparison', ''))

                cost_json = os.path.join(server_output_dir, 'cost-estimate.json')
                with open(cost_json, 'w') as f:
                    json.dump(report, f, indent=2)

                outputs['cost_estimate'] = cost_path
            except Exception as e:
                logger.warning(f"Could not generate cost estimate for {hostname}: {e}")

        return outputs

    def process_servers(
        self,
        servers: List[ServerEntry],
        default_key: str = None,
        parallel: int = 1
    ) -> Dict[str, Any]:
        """Process all servers"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total': len(servers),
            'successful': 0,
            'failed': 0,
            'servers': {},
            'errors': {}
        }

        if parallel > 1:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(self._process_single_server, server, default_key): server
                    for server in servers
                }

                for future in as_completed(futures):
                    server = futures[future]
                    try:
                        result = future.result()
                        if result:
                            results['servers'][server.hostname] = result
                            results['successful'] += 1
                        else:
                            results['failed'] += 1
                            results['errors'][server.hostname] = self.errors.get(server.hostname, 'Unknown error')
                    except Exception as e:
                        results['failed'] += 1
                        results['errors'][server.hostname] = str(e)
        else:
            # Sequential processing
            for server in servers:
                result = self._process_single_server(server, default_key)
                if result:
                    results['servers'][server.hostname] = result
                    results['successful'] += 1
                else:
                    results['failed'] += 1
                    results['errors'][server.hostname] = self.errors.get(server.hostname, 'Unknown error')

        return results

    def _process_single_server(self, server: ServerEntry, default_key: str) -> Optional[Dict]:
        """Process a single server (analysis + generation)"""
        data = self.analyze_server(server, default_key)
        if not data:
            return None

        # Generate outputs
        server_output_dir = os.path.join(self.output_dir, server.hostname)
        outputs = self.generate_outputs(server.hostname, data, server_output_dir)

        return {
            'hostname': server.hostname,
            'groups': server.groups,
            'summary': data.get('summary', {}),
            'outputs': outputs,
            'os_info': data.get('os_info', {})
        }

    def generate_summary_report(self, results: Dict) -> str:
        """Generate a summary report for all servers"""
        report_path = os.path.join(self.output_dir, 'batch-summary.md')

        with open(report_path, 'w') as f:
            f.write("# Batch Analysis Summary\n\n")
            f.write(f"**Generated:** {results['timestamp']}\n\n")
            f.write(f"**Total Servers:** {results['total']}\n")
            f.write(f"**Successful:** {results['successful']}\n")
            f.write(f"**Failed:** {results['failed']}\n\n")
            f.write("---\n\n")

            # Successful servers
            if results['servers']:
                f.write("## Analyzed Servers\n\n")
                f.write("| Hostname | Purpose | Services | Status |\n")
                f.write("|----------|---------|----------|--------|\n")

                for hostname, data in results['servers'].items():
                    summary = data.get('summary', {})
                    purpose = summary.get('server_purpose', 'Unknown')[:30]
                    service_count = summary.get('service_count', 0)
                    issues = len(summary.get('potential_issues', []))
                    status = f"⚠️ {issues} issues" if issues > 0 else "✓ OK"
                    f.write(f"| {hostname} | {purpose} | {service_count} | {status} |\n")

                f.write("\n")

            # Failed servers
            if results['errors']:
                f.write("## Failed Servers\n\n")
                f.write("| Hostname | Error |\n")
                f.write("|----------|-------|\n")
                for hostname, error in results['errors'].items():
                    f.write(f"| {hostname} | {error[:50]} |\n")
                f.write("\n")

            # Cost comparison
            if self.include_cloud and results['servers']:
                f.write("## Cost Comparison\n\n")
                f.write("| Hostname | AWS/year | GCP/year | Azure/year |\n")
                f.write("|----------|----------|----------|------------|\n")

                for hostname, data in results['servers'].items():
                    cost_json = os.path.join(self.output_dir, hostname, 'cost-estimate.json')
                    if os.path.exists(cost_json):
                        with open(cost_json, 'r') as cf:
                            costs = json.load(cf)
                            estimates = costs.get('estimates', {})
                            aws = estimates.get('aws', {}).get('annual_cost', 0)
                            gcp = estimates.get('gcp', {}).get('annual_cost', 0)
                            azure = estimates.get('azure', {}).get('annual_cost', 0)
                            f.write(f"| {hostname} | ${aws:,.0f} | ${gcp:,.0f} | ${azure:,.0f} |\n")

        # Also save JSON results
        json_path = os.path.join(self.output_dir, 'batch-summary.json')
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        return report_path

    @staticmethod
    def generate_csv_template(output_path: str = 'servers.csv') -> str:
        """Generate a CSV template file"""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['hostname', 'username', 'port', 'private_key', 'sudo_password', 'groups', 'notes'])
            writer.writerow(['server1.example.com', 'ubuntu', '22', '~/.ssh/id_rsa', '', 'web', 'Production web server'])
            writer.writerow(['server2.example.com', 'admin', '22', '~/.ssh/id_rsa', 'sudopass', 'db', 'Database server'])
            writer.writerow(['192.168.1.100', 'root', '22', '~/.ssh/id_ed25519', '', 'internal', 'Internal server'])

        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='Batch analyze multiple servers from CSV'
    )
    parser.add_argument(
        'csv_file',
        nargs='?',
        help='Path to CSV file with server list'
    )
    parser.add_argument(
        '-o', '--output',
        default='output',
        help='Output directory (default: output)'
    )
    parser.add_argument(
        '-k', '--key',
        help='Default SSH private key path'
    )
    parser.add_argument(
        '-p', '--parallel',
        type=int,
        default=1,
        help='Number of parallel connections (default: 1)'
    )
    parser.add_argument(
        '--no-cloud',
        action='store_true',
        help='Skip cloud provider generation'
    )
    parser.add_argument(
        '--template',
        action='store_true',
        help='Generate a CSV template file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.template:
        path = BatchProcessor.generate_csv_template()
        print(f"CSV template generated: {path}")
        return

    if not args.csv_file:
        parser.print_help()
        print("\nError: CSV file required (or use --template to generate one)")
        sys.exit(1)

    processor = BatchProcessor(
        output_dir=args.output,
        include_cloud=not args.no_cloud
    )

    servers = processor.load_csv(args.csv_file)
    if not servers:
        print("No servers found in CSV file")
        sys.exit(1)

    print(f"\nProcessing {len(servers)} servers...")

    results = processor.process_servers(
        servers,
        default_key=args.key,
        parallel=args.parallel
    )

    report_path = processor.generate_summary_report(results)

    print(f"\n{'='*60}")
    print(f"Batch processing complete!")
    print(f"  Successful: {results['successful']}/{results['total']}")
    print(f"  Failed: {results['failed']}/{results['total']}")
    print(f"  Summary: {report_path}")
    print(f"  Output: {args.output}/")


if __name__ == '__main__':
    main()
