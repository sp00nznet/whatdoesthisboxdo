"""
Documentation Generator
Generates beautiful, opinionated documentation about the analyzed system
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class DocumentationGenerator:
    """Generates comprehensive, pretty system documentation with analysis opinions"""

    def __init__(self, analysis_data: Dict[str, Any]):
        self.data = analysis_data
        self.hostname = analysis_data.get('hostname', 'unknown')
        self.os_info = analysis_data.get('os_info', {})
        self.os_type = analysis_data.get('os_type', 'linux')

    def _get_os_display_name(self) -> str:
        """Get the OS display name, handling both Linux and Windows"""
        if self.os_type == 'windows':
            # Windows: use 'name' key (e.g., "Microsoft Windows Server 2022 Standard")
            return self.os_info.get('name', 'Windows Server')
        else:
            # Linux: use 'distro' key
            return self.os_info.get('distro', 'Linux')

    def _get_os_version(self) -> str:
        """Get the OS version, handling both Linux and Windows"""
        if self.os_type == 'windows':
            # Windows: combine version and build
            version = self.os_info.get('version', '')
            build = self.os_info.get('build', '')
            if build:
                return f"Build {build}"
            return version or ''
        else:
            return self.os_info.get('version', '')

    def generate(self, output_path: str) -> str:
        """Generate full documentation"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)

        doc = self._generate_header()
        doc += self._generate_executive_summary()
        doc += self._generate_system_identity()
        doc += self._generate_external_sources_section()
        doc += self._generate_gitlab_findings()
        doc += self._generate_harbor_findings()
        doc += self._generate_virtualization_findings()
        doc += self._generate_health_assessment()
        doc += self._generate_metrics_section()
        doc += self._generate_services_section()
        doc += self._generate_network_section()
        doc += self._generate_storage_section()
        doc += self._generate_secrets_section()
        doc += self._generate_security_assessment()
        doc += self._generate_configuration_section()
        doc += self._generate_dependencies_section()
        doc += self._generate_recommendations()
        doc += self._generate_scaling_section()
        doc += self._generate_containerization_section()
        doc += self._generate_config_improvements_section()
        doc += self._generate_footer()

        with open(output_path, 'w') as f:
            f.write(doc)

        logger.info(f"Documentation generated: {output_path}")
        return output_path

    def _generate_header(self) -> str:
        """Generate beautiful document header"""
        os_name = self._get_os_display_name()
        os_version = self._get_os_version()

        return f"""<div align="center">

# {self.hostname}

### System Documentation & Analysis Report

---

**{os_name} {os_version}** | **Generated {datetime.now().strftime('%B %d, %Y at %H:%M')}**

</div>

---

"""

    def _generate_executive_summary(self) -> str:
        """Generate executive summary with server purpose determination"""
        summary = self.data.get('summary', {})
        purpose = summary.get('server_purpose', '')
        key_services = summary.get('key_services', [])

        doc = """## Executive Summary

"""
        # Determine what this server does based on analysis
        server_role = self._determine_server_role()

        doc += f"""### What Does This Server Do?

{server_role['description']}

"""

        if server_role['role_type']:
            doc += f"""<table>
<tr>
<td><strong>Primary Role</strong></td>
<td>{server_role['role_type']}</td>
</tr>
<tr>
<td><strong>Confidence</strong></td>
<td>{'High' if server_role['confidence'] > 0.7 else 'Medium' if server_role['confidence'] > 0.4 else 'Low'}</td>
</tr>
</table>

"""

        if key_services:
            doc += """### Key Services Running

| Service | Status | Significance |
|---------|--------|--------------|
"""
            for svc in key_services[:8]:
                significance = self._get_service_significance(svc.get('name', ''))
                doc += f"| **{svc.get('name', 'Unknown')}** | {svc.get('status', 'Unknown')} | {significance} |\n"
            doc += "\n"

        return doc

    def _determine_server_role(self) -> Dict[str, Any]:
        """Analyze and determine the server's primary role with confidence"""
        services = self.data.get('processes', {}).get('services', [])
        processes = self.data.get('processes', {}).get('running', [])
        packages = self.data.get('files', {}).get('installed_packages', [])
        ports = self.data.get('processes', {}).get('listening_ports', [])

        # Handle both active states for Linux and Windows
        service_names = [s.get('name', '').lower() for s in services
                        if s.get('active') in ['active', 'running'] or s.get('status') in ['running', 'Running']]
        process_names = [p.get('name', '').lower() for p in processes]
        package_names = [p.get('name', '').lower() for p in packages]
        port_numbers = [p.get('port', 0) for p in ports]

        # Combine service and process names for detection
        all_running = set(service_names + process_names)

        roles = []

        # ===================
        # WINDOWS-SPECIFIC DETECTION
        # ===================

        # Veeam Backup Server Detection
        veeam_indicators = ['veeam', 'veeambackup', 'veeamagent', 'veeamtransport', 'veeamdeploysvc']
        if any(v in name for name in all_running for v in veeam_indicators):
            roles.append(('Backup Server (Veeam)', 0.95, 'Enterprise backup and disaster recovery using Veeam'))

        # Microsoft SQL Server Detection
        mssql_indicators = ['mssqlserver', 'sqlservr', 'mssql', 'sqlwriter', 'sqlagent', 'msdtssrvr']
        if any(m in name for name in all_running for m in mssql_indicators):
            roles.append(('Database Server (MSSQL)', 0.95, 'Microsoft SQL Server relational database'))

        # IIS Web Server Detection
        iis_indicators = ['w3svc', 'iisexpress', 'w3wp', 'inetinfo', 'was']
        if any(i in name for name in all_running for i in iis_indicators):
            roles.append(('Web Server (IIS)', 0.9, 'Microsoft IIS web server'))

        # Active Directory / Domain Controller Detection
        ad_indicators = ['ntds', 'adws', 'kdc', 'netlogon', 'dfsr', 'ntfrs', 'dns', 'ismserv']
        ad_count = sum(1 for a in ad_indicators if any(a in name for name in all_running))
        if ad_count >= 3:
            roles.append(('Domain Controller', 0.95, 'Active Directory Domain Services'))
        elif ad_count >= 1:
            roles.append(('AD Member Server', 0.7, 'Active Directory integrated server'))

        # Exchange Server Detection
        exchange_indicators = ['msexchangetransport', 'msexchangeis', 'msexchange', 'edgetransport']
        if any(e in name for name in all_running for e in exchange_indicators):
            roles.append(('Mail Server (Exchange)', 0.95, 'Microsoft Exchange email server'))

        # Hyper-V Virtualization Detection
        hyperv_indicators = ['vmms', 'vmcompute', 'vmwp', 'hvax', 'vmicheartbeat']
        if any(h in name for name in all_running for h in hyperv_indicators):
            roles.append(('Virtualization Host (Hyper-V)', 0.9, 'Microsoft Hyper-V virtualization'))

        # Windows Server Update Services (WSUS)
        if any('wsus' in name or 'updateservices' in name for name in all_running):
            roles.append(('Update Server (WSUS)', 0.9, 'Windows Server Update Services'))

        # Remote Desktop Services
        rds_indicators = ['termservice', 'sessionenv', 'umrdpservice', 'rdagentbootloader']
        if any(r in name for name in all_running for r in rds_indicators):
            roles.append(('Remote Desktop Server', 0.85, 'Remote Desktop Services / Terminal Server'))

        # Print Server Detection
        if any('spooler' in name or 'printnotify' in name for name in all_running):
            roles.append(('Print Server', 0.7, 'Windows Print Services'))

        # DHCP Server
        if any('dhcpserver' in name for name in all_running):
            roles.append(('DHCP Server', 0.9, 'Dynamic Host Configuration Protocol server'))

        # Windows DNS Server (separate from AD)
        if any('dns' in name for name in all_running) and 'Domain Controller' not in [r[0] for r in roles]:
            roles.append(('DNS Server', 0.8, 'Domain Name System server'))

        # SCCM / Configuration Manager
        sccm_indicators = ['ccmexec', 'smsagenthost', 'sccm', 'smsexec']
        if any(s in name for name in all_running for s in sccm_indicators):
            roles.append(('SCCM Server', 0.85, 'System Center Configuration Manager'))

        # ===================
        # LINUX/CROSS-PLATFORM DETECTION
        # ===================

        # Web Server Detection (Linux)
        web_indicators = ['nginx', 'apache2', 'httpd', 'caddy', 'lighttpd']
        if any(w in name for name in all_running for w in web_indicators):
            roles.append(('Web Server', 0.9, 'Serves HTTP/HTTPS traffic to clients'))

        # Database Detection (Linux/Cross-platform)
        db_indicators = {
            'mysql': 'MySQL relational database',
            'mariadb': 'MariaDB relational database',
            'postgresql': 'PostgreSQL relational database',
            'postgres': 'PostgreSQL relational database',
            'mongodb': 'MongoDB document database',
            'mongod': 'MongoDB document database',
            'redis': 'Redis in-memory data store',
            'elasticsearch': 'Elasticsearch search engine',
        }
        for db, desc in db_indicators.items():
            if any(db in name for name in all_running):
                roles.append(('Database Server', 0.9, f'Runs {desc}'))
                break  # Only add once

        # Container/Orchestration Detection
        if any('docker' in name or 'containerd' in name for name in all_running):
            if any('kubelet' in name or 'k3s' in name for name in all_running):
                roles.append(('Kubernetes Node', 0.9, 'Part of a Kubernetes cluster'))
            else:
                roles.append(('Container Host', 0.85, 'Runs containerized applications via Docker'))

        # CI/CD Detection
        ci_indicators = ['gitlab-runner', 'jenkins', 'drone', 'buildkite', 'teamcity', 'azureagent']
        if any(ci in name for name in all_running for ci in ci_indicators):
            roles.append(('CI/CD Runner', 0.85, 'Executes continuous integration/deployment pipelines'))

        # Monitoring Detection
        mon_indicators = ['prometheus', 'grafana', 'zabbix', 'nagios', 'influxdb', 'telegraf', 'datadog']
        if any(m in name for name in all_running for m in mon_indicators):
            roles.append(('Monitoring Server', 0.8, 'Collects and visualizes system metrics'))

        # Mail Server Detection (Linux)
        if any(m in name for name in all_running for m in ['postfix', 'dovecot', 'exim', 'sendmail']):
            roles.append(('Mail Server', 0.85, 'Handles email sending/receiving'))

        # File Server Detection (Linux)
        if any(f in name for name in all_running for f in ['smbd', 'nfs', 'vsftpd', 'proftpd']):
            roles.append(('File Server', 0.8, 'Provides file sharing services'))

        # Load Balancer Detection
        if any(lb in name for name in all_running for lb in ['haproxy', 'traefik', 'envoy']):
            roles.append(('Load Balancer', 0.85, 'Distributes traffic across backend servers'))

        # VPN/Gateway Detection
        if any(v in name for name in all_running for v in ['openvpn', 'wireguard', 'strongswan']):
            roles.append(('VPN Gateway', 0.8, 'Provides secure network access'))

        # VMware Detection
        vmware_indicators = ['vmware', 'vmtoolsd', 'vmware-tools']
        if any(v in name for name in all_running for v in vmware_indicators):
            # This is a VM, not a host - don't add as a role
            pass

        # Application Server Detection (generic)
        app_ports = [3000, 4000, 5000, 8000, 8080, 8443, 9000]
        if any(p in port_numbers for p in app_ports) and not roles:
            roles.append(('Application Server', 0.6, 'Runs custom application services'))

        # Build final assessment
        if not roles:
            return {
                'role_type': 'General Purpose Server',
                'confidence': 0.3,
                'description': "This server's primary purpose could not be clearly determined from the analysis. It may be a general-purpose system or have a specialized role not detected by standard service patterns."
            }

        # Sort by confidence and combine
        roles.sort(key=lambda x: x[1], reverse=True)
        primary_role = roles[0]

        if len(roles) == 1:
            description = f"This server functions as a **{primary_role[0]}**. {primary_role[2]}."
        else:
            secondary_roles = ', '.join([r[0] for r in roles[1:3]])
            description = f"This server primarily functions as a **{primary_role[0]}** ({primary_role[2]}), with additional roles as {secondary_roles}."

        return {
            'role_type': primary_role[0],
            'confidence': primary_role[1],
            'description': description,
            'all_roles': roles
        }

    def _get_service_significance(self, service_name: str) -> str:
        """Get a human-readable significance for a service"""
        significance_map = {
            # Linux services
            'nginx': 'Reverse proxy / Web server',
            'apache2': 'Web server',
            'httpd': 'Web server',
            'mysql': 'Primary database',
            'mariadb': 'Primary database',
            'postgresql': 'Primary database',
            'mongodb': 'Document database',
            'redis': 'Caching / Session store',
            'docker': 'Container runtime',
            'containerd': 'Container runtime',
            'sshd': 'Remote access',
            'cron': 'Scheduled tasks',
            'systemd': 'System init',
            'prometheus': 'Metrics collection',
            'grafana': 'Metrics visualization',
            'haproxy': 'Load balancing',
            'postfix': 'Mail delivery',
            'kubelet': 'Kubernetes node agent',
            # Windows services
            'w3svc': 'IIS Web Server',
            'iisadmin': 'IIS Administration',
            'mssqlserver': 'SQL Server Database',
            'sqlserveragent': 'SQL Server Agent (jobs)',
            'sqlwriter': 'SQL Server VSS Writer',
            'veeambackupsvc': 'Veeam Backup Service',
            'veeamtransportsvc': 'Veeam Data Transport',
            'veeamdeploysvc': 'Veeam Deployment',
            'veeamnfssvc': 'Veeam NFS Service',
            'vmms': 'Hyper-V Management',
            'vmcompute': 'Hyper-V Compute',
            'ntds': 'Active Directory',
            'kdc': 'Kerberos Key Distribution',
            'netlogon': 'AD Net Logon',
            'dns': 'DNS Server',
            'dhcpserver': 'DHCP Server',
            'termservice': 'Remote Desktop Services',
            'spooler': 'Print Spooler',
            'wuauserv': 'Windows Update',
            'wsusservice': 'WSUS Server',
            'msexchangetransport': 'Exchange Transport',
            'msexchangeis': 'Exchange Information Store',
            'bits': 'Background Transfer',
            'lanmanserver': 'File Sharing (SMB)',
            'lanmanworkstation': 'SMB Client',
            'winrm': 'Remote Management',
            'eventlog': 'Event Logging',
            'ccmexec': 'SCCM Client Agent',
            'wlansvc': 'Wireless LAN',
            'mpssvc': 'Windows Firewall',
            'windefend': 'Windows Defender',
            'seclogon': 'Secondary Logon',
        }
        name_lower = service_name.lower()
        # Direct match first
        if name_lower in significance_map:
            return significance_map[name_lower]
        # Partial match for Windows services that may have different names
        for key, value in significance_map.items():
            if key in name_lower or name_lower in key:
                return value
        return 'System service'

    def _generate_system_identity(self) -> str:
        """Generate system identity section"""
        resource = self.data.get('processes', {}).get('resource_usage', {})
        cpu = resource.get('cpu', {})
        memory = resource.get('memory', {})

        total_mem_gb = round(memory.get('total', 0) / 1024 / 1024 / 1024, 1)
        cpu_count = cpu.get('count', 'N/A')

        os_name = self._get_os_display_name()
        os_version = self._get_os_version()

        # Third row depends on OS type
        if self.os_type == 'windows':
            third_row_label = "Build"
            third_row_value = self.os_info.get('build', 'Unknown')
        else:
            third_row_label = "Kernel"
            third_row_value = self.os_info.get('kernel', 'Unknown')

        doc = """## System Identity

"""
        # Calculate padding for third row
        third_row_padding = 55 - len(third_row_label)
        third_row_formatted = f"{third_row_value:<{third_row_padding}}"

        doc += f"""```
+{'='*60}+
|  HOSTNAME: {self.hostname:<47} |
+{'='*60}+
|  OS: {os_name:<52} |
|  Version: {os_version:<47} |
|  {third_row_label}: {third_row_formatted} |
+{'-'*60}+
|  CPUs: {str(cpu_count):<53} |
|  Memory: {str(total_mem_gb) + ' GB':<51} |
+{'='*60}+
```

"""
        return doc

    def _generate_external_sources_section(self) -> str:
        """Generate external sources status section"""
        sources = self.data.get('external_sources', {})

        if not sources:
            return ""

        doc = """## External Data Sources

| Source | Status | Details |
|--------|--------|---------|
"""
        source_names = {
            'gitlab': 'GitLab',
            'harbor': 'Harbor Registry',
            'vcenter': 'vCenter/vSphere',
            'proxmox': 'Proxmox'
        }

        for key, name in source_names.items():
            info = sources.get(key, {})
            if info.get('data_collected'):
                status = "Connected"
                details = "Data collected successfully"
            elif info.get('connected'):
                status = "Connected"
                details = "Connected but no relevant data found"
            elif info.get('configured'):
                status = "Failed"
                details = info.get('error', 'Connection failed')
            else:
                status = "Not Configured"
                details = f"Set credentials in .env file"

            doc += f"| {name} | {status} | {details} |\n"

        doc += "\n"

        # Add note about configuring sources
        unconfigured = [name for key, name in source_names.items()
                       if not sources.get(key, {}).get('configured')]
        if unconfigured:
            doc += f"""> **Note:** To enable {', '.join(unconfigured)}, configure credentials in `.env` file.
> See `.env.example` for required variables.

"""
        return doc

    def _generate_gitlab_findings(self) -> str:
        """Generate GitLab findings section"""
        gitlab = self.data.get('gitlab', {})
        matches = self.data.get('path_repo_matches', [])
        ext = self.data.get('external_sources', {}).get('gitlab', {})

        if not ext.get('data_collected'):
            return ""

        doc = """## GitLab Repository Analysis

"""
        if matches:
            doc += """### Related Repositories Found

| Repository | Match Type | Reason |
|------------|------------|--------|
"""
            for match in matches[:15]:
                doc += f"| `{match.get('project', 'N/A')}` | {match.get('type', 'N/A')} | {match.get('match_reason', '')} |\n"
            doc += "\n"

            # Show URLs
            doc += "**Repository Links:**\n\n"
            seen_urls = set()
            for match in matches[:10]:
                url = match.get('url', '')
                if url and url not in seen_urls:
                    doc += f"- {url}\n"
                    seen_urls.add(url)
            doc += "\n"
        else:
            doc += "> No GitLab repositories found matching this server's hostname or configuration.\n\n"

        # Show relevant CI/CD configs
        configs = gitlab.get('related_configs', [])
        if configs:
            doc += """### Infrastructure-as-Code Found

| Project | File |
|---------|------|
"""
            for cfg in configs[:10]:
                doc += f"| `{cfg.get('project', '')}` | `{cfg.get('file', '')}` |\n"
            doc += "\n"

        # Show recent deployments
        deployments = gitlab.get('deployments', [])
        if deployments:
            doc += """### Recent Deployments

| Project | Environment | URL |
|---------|-------------|-----|
"""
            for dep in deployments[:10]:
                doc += f"| `{dep.get('project', '')}` | {dep.get('environment', '')} | {dep.get('external_url', 'N/A')} |\n"
            doc += "\n"

        return doc

    def _generate_harbor_findings(self) -> str:
        """Generate Harbor findings section"""
        harbor = self.data.get('harbor', {})
        matches = self.data.get('container_registry_matches', [])
        ext = self.data.get('external_sources', {}).get('harbor', {})

        if not ext.get('data_collected'):
            return ""

        doc = """## Harbor Container Registry Analysis

"""
        if matches:
            doc += """### Container Image Matches

| Local Image | Harbor Repository | Tags | Vulnerabilities |
|-------------|-------------------|------|-----------------|
"""
            for match in matches[:15]:
                vulns = match.get('vulnerabilities', {})
                vuln_str = f"C:{vulns.get('critical', 0)} H:{vulns.get('high', 0)}" if vulns else "N/A"
                tags = ', '.join(match.get('tags', [])[:3]) or 'N/A'
                doc += f"| `{match.get('local_image', 'N/A')}` | `{match.get('harbor_repo', '')}` | {tags} | {vuln_str} |\n"
            doc += "\n"
        else:
            doc += "> No Harbor images found matching running containers on this server.\n\n"

        # Show summary stats
        projects = harbor.get('projects', [])
        repos = harbor.get('repositories', [])
        if projects:
            doc += f"""### Registry Summary

- **Projects:** {len(projects)}
- **Repositories:** {len(repos)}

"""
        return doc

    def _generate_virtualization_findings(self) -> str:
        """Generate virtualization findings section"""
        virt = self.data.get('virtualization', {})
        ext_vcenter = self.data.get('external_sources', {}).get('vcenter', {})
        ext_proxmox = self.data.get('external_sources', {}).get('proxmox', {})

        if not ext_vcenter.get('data_collected') and not ext_proxmox.get('data_collected'):
            return ""

        platform = virt.get('platform', 'unknown').title()
        this_vm = virt.get('this_vm', {})

        doc = f"""## {platform} VM Information

"""
        if this_vm:
            doc += """### This VM's Configuration

| Property | Value |
|----------|-------|
"""
            for key, value in this_vm.items():
                if key not in ['id', 'uuid'] and value:
                    doc += f"| {key.replace('_', ' ').title()} | {value} |\n"
            doc += "\n"
        else:
            doc += f"> VM details for this hostname not found in {platform}.\n\n"

        # Show cluster/host info if available
        data = virt.get('data', {})
        if isinstance(data, dict):
            if data.get('cluster'):
                doc += f"**Cluster:** {data.get('cluster')}\n\n"
            if data.get('host'):
                doc += f"**Host:** {data.get('host')}\n\n"
            if data.get('datastore'):
                doc += f"**Datastore:** {data.get('datastore')}\n\n"

        return doc

    def _generate_health_assessment(self) -> str:
        """Generate health assessment with visual indicators"""
        metrics = self.data.get('metrics_analysis', {})

        if not metrics:
            return ""

        health_score = metrics.get('health_score', 0)
        overall = metrics.get('overall_status', 'unknown')
        assessment = metrics.get('assessment', '')
        warnings = metrics.get('warnings', [])
        insights = metrics.get('insights', [])

        # Health bar visualization
        filled = int(health_score / 10)
        empty = 10 - filled

        if health_score >= 80:
            status_emoji = "[HEALTHY]"
            bar_char = "#"
        elif health_score >= 60:
            status_emoji = "[FAIR]"
            bar_char = "#"
        else:
            status_emoji = "[CRITICAL]"
            bar_char = "!"

        health_bar = f"[{bar_char * filled}{'-' * empty}]"

        doc = f"""## Health Assessment

### Overall Health Score

```
{status_emoji}  {health_bar}  {health_score}/100

{assessment}
```

"""

        if warnings:
            doc += """### Warnings

"""
            for warning in warnings:
                doc += f"- **{warning}**\n"
            doc += "\n"

        if insights:
            doc += """### Insights

"""
            for insight in insights:
                doc += f"- {insight}\n"
            doc += "\n"

        return doc

    def _generate_metrics_section(self) -> str:
        """Generate metrics section with collected data"""
        metrics = self.data.get('metrics_analysis', {})
        summary = metrics.get('metrics_summary', {})

        if not summary:
            # Fall back to point-in-time data
            resource = self.data.get('processes', {}).get('resource_usage', {})
            if not resource:
                return ""

            cpu = resource.get('cpu', {})
            memory = resource.get('memory', {})

            doc = """## Resource Metrics

> *Point-in-time snapshot. Use `--monitor <seconds>` for time-series analysis.*

"""
            doc += "### Current Usage\n\n"
            doc += "| Metric | Value | Assessment |\n"
            doc += "|--------|-------|------------|\n"

            mem_percent = memory.get('percent', 0)
            load_avg = cpu.get('load_avg', [0])[0] if cpu.get('load_avg') else 0

            doc += f"| Memory Usage | {mem_percent}% | {self._assess_value(mem_percent, 70, 85)} |\n"
            doc += f"| Load Average (1m) | {load_avg} | {self._assess_load(load_avg, cpu.get('count', 1))} |\n"
            doc += f"| CPU Cores | {cpu.get('count', 'N/A')} | - |\n\n"
            return doc

        doc = f"""## Resource Metrics

> *Collected over {int(self.data.get('monitoring_duration', 0))} seconds*

### Usage Summary

| Metric | Average | Maximum | Assessment |
|--------|---------|---------|------------|
| CPU Usage | {summary.get('cpu_avg', 0):.1f}% | {summary.get('cpu_max', 0):.1f}% | {self._assess_value(summary.get('cpu_avg', 0), 60, 80)} |
| Memory Usage | {summary.get('memory_avg', 0):.1f}% | {summary.get('memory_max', 0):.1f}% | {self._assess_value(summary.get('memory_avg', 0), 70, 85)} |
| System Load | {summary.get('load_avg', 0):.2f} | - | {self._assess_load(summary.get('load_avg', 0), 1)} |

### I/O Activity

| Type | Rate | Assessment |
|------|------|------------|
| Disk Read | {summary.get('disk_read_mb_s', 0):.2f} MB/s | {self._assess_io(summary.get('disk_read_mb_s', 0))} |
| Disk Write | {summary.get('disk_write_mb_s', 0):.2f} MB/s | {self._assess_io(summary.get('disk_write_mb_s', 0))} |
| Network In | {summary.get('net_recv_mb_s', 0):.2f} MB/s | - |
| Network Out | {summary.get('net_sent_mb_s', 0):.2f} MB/s | - |

"""
        return doc

    def _assess_value(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Assess a metric value and return status"""
        if value >= critical_threshold:
            return "CRITICAL - Immediate attention needed"
        elif value >= warning_threshold:
            return "WARNING - Monitor closely"
        elif value < 20:
            return "LOW - Possibly overprovisioned"
        else:
            return "HEALTHY"

    def _assess_load(self, load: float, cpu_count: int) -> str:
        """Assess system load"""
        if load > cpu_count * 2:
            return "CRITICAL - System overloaded"
        elif load > cpu_count:
            return "WARNING - High load"
        elif load < 0.5:
            return "LOW - Minimal load"
        else:
            return "HEALTHY"

    def _assess_io(self, mb_per_sec: float) -> str:
        """Assess I/O rate"""
        if mb_per_sec > 100:
            return "HIGH - Potential bottleneck"
        elif mb_per_sec > 50:
            return "MODERATE - Active I/O"
        else:
            return "LOW"

    def _generate_services_section(self) -> str:
        """Generate services section with opinions"""
        services = self.data.get('processes', {}).get('services', [])
        processes = self.data.get('processes', {}).get('running', [])

        doc = """## Services & Processes

### Active Services

"""
        active_services = [s for s in services if s.get('active') == 'active']

        if active_services:
            # Group services by type
            critical_services = []
            application_services = []
            system_services = []

            for svc in active_services:
                name = svc.get('name', '').lower()
                if any(c in name for c in ['nginx', 'apache', 'mysql', 'postgres', 'redis', 'docker', 'haproxy']):
                    critical_services.append(svc)
                elif any(a in name for a in ['node', 'python', 'java', 'go', 'ruby', 'php']):
                    application_services.append(svc)
                else:
                    system_services.append(svc)

            if critical_services:
                doc += "**Critical Infrastructure Services:**\n\n"
                doc += "| Service | Status | Opinion |\n"
                doc += "|---------|--------|--------|\n"
                for svc in critical_services[:10]:
                    opinion = self._get_service_opinion(svc)
                    doc += f"| `{svc.get('name')}` | {svc.get('status')} | {opinion} |\n"
                doc += "\n"

            if application_services:
                doc += "**Application Services:**\n\n"
                for svc in application_services[:5]:
                    doc += f"- `{svc.get('name')}` - {svc.get('description', 'No description')[:60]}\n"
                doc += "\n"

            doc += f"<details>\n<summary><strong>All {len(active_services)} Active Services</strong></summary>\n\n"
            doc += "| Service | Status |\n|---------|--------|\n"
            for svc in active_services:
                doc += f"| {svc.get('name')} | {svc.get('status')} |\n"
            doc += "\n</details>\n\n"

        # Top processes
        if processes:
            sorted_procs = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)

            doc += """### Resource-Intensive Processes

| Process | User | CPU % | MEM % | Assessment |
|---------|------|-------|-------|------------|
"""
            for proc in sorted_procs[:10]:
                assessment = self._assess_process(proc)
                doc += f"| `{proc.get('name', 'N/A')[:20]}` | {proc.get('user', 'N/A')} | {proc.get('cpu_percent', 0):.1f} | {proc.get('memory_percent', 0):.1f} | {assessment} |\n"

            doc += "\n"

        return doc

    def _get_service_opinion(self, service: Dict) -> str:
        """Get an opinion about a service"""
        name = service.get('name', '').lower()
        status = service.get('status', '')

        opinions = {
            'nginx': 'Industry-standard reverse proxy - good choice',
            'apache2': 'Mature web server - consider nginx for better performance',
            'mysql': 'Reliable RDBMS - ensure regular backups',
            'postgresql': 'Excellent RDBMS choice - feature-rich and performant',
            'redis': 'Fast caching layer - monitor memory usage',
            'docker': 'Container runtime active - good for deployment flexibility',
            'mongodb': 'Document DB - ensure proper indexing',
        }

        for key, opinion in opinions.items():
            if key in name:
                return opinion

        if status == 'running':
            return 'Running normally'
        return status

    def _assess_process(self, proc: Dict) -> str:
        """Assess a process"""
        cpu = proc.get('cpu_percent', 0)
        mem = proc.get('memory_percent', 0)

        if cpu > 50:
            return "High CPU - investigate"
        elif mem > 20:
            return "High memory usage"
        elif cpu < 1 and mem < 1:
            return "Idle"
        return "Normal"

    def _generate_network_section(self) -> str:
        """Generate network section"""
        listening = self.data.get('processes', {}).get('listening_ports', [])
        connections = self.data.get('processes', {}).get('connections', [])

        doc = """## Network Configuration

### Exposed Services

"""
        if listening:
            # Group by risk level
            high_risk_ports = [21, 23, 25, 110, 143, 445, 3389]
            standard_ports = [22, 80, 443]

            doc += "| Port | Service | Binding | Risk Assessment |\n"
            doc += "|------|---------|---------|----------------|\n"

            for port in sorted(listening, key=lambda x: x.get('port', 0)):
                port_num = port.get('port', 0)
                addr = port.get('addr', '*')
                process = port.get('process', 'unknown')

                if addr in ['0.0.0.0', '*', '::']:
                    binding = "All interfaces (public)"
                    if port_num in high_risk_ports:
                        risk = "HIGH - Sensitive service exposed"
                    elif port_num not in standard_ports and port_num > 1024:
                        risk = "MEDIUM - Non-standard port exposed"
                    else:
                        risk = "Standard"
                else:
                    binding = f"Local only ({addr})"
                    risk = "LOW - Internal only"

                doc += f"| {port_num} | {process[:25]} | {binding} | {risk} |\n"

            doc += "\n"

        # Connection summary
        established = [c for c in connections if c.get('status') == 'ESTABLISHED']
        if established:
            doc += f"""### Active Connections

**{len(established)}** established connections detected.

"""
            # Group by remote host
            remote_hosts = {}
            for conn in established:
                remote = conn.get('remote_addr', 'unknown')
                if remote not in remote_hosts:
                    remote_hosts[remote] = 0
                remote_hosts[remote] += 1

            if len(remote_hosts) > 1:
                doc += "**Top Remote Hosts:**\n\n"
                for host, count in sorted(remote_hosts.items(), key=lambda x: x[1], reverse=True)[:5]:
                    doc += f"- `{host}`: {count} connections\n"
                doc += "\n"

        return doc

    def _generate_storage_section(self) -> str:
        """Generate storage section with warnings"""
        disk_usage = self.data.get('processes', {}).get('resource_usage', {}).get('disk', {})

        doc = """## Storage Analysis

"""
        if disk_usage:
            doc += "### Disk Usage\n\n"
            doc += "| Mount | Size | Used | Free | Status |\n"
            doc += "|-------|------|------|------|--------|\n"

            for mount, usage in disk_usage.items():
                total_gb = round(usage.get('total', 0) / 1024 / 1024 / 1024, 1)
                used_gb = round(usage.get('used', 0) / 1024 / 1024 / 1024, 1)
                free_gb = round(usage.get('free', 0) / 1024 / 1024 / 1024, 1)
                percent = usage.get('percent', 0)

                if percent >= 90:
                    status = "CRITICAL - Nearly full!"
                elif percent >= 80:
                    status = "WARNING - Getting full"
                elif percent >= 70:
                    status = "Monitor"
                else:
                    status = "Healthy"

                doc += f"| `{mount}` | {total_gb} GB | {used_gb} GB | {free_gb} GB | {status} |\n"

            doc += "\n"

        return doc

    def _generate_secrets_section(self) -> str:
        """Generate SSH keys and GPG keyrings section"""
        secrets = self.data.get('secrets', {})

        if not secrets:
            return ""

        ssh_keys = secrets.get('ssh_keys', [])
        gpg_keyrings = secrets.get('gpg_keyrings', [])
        other_keys = secrets.get('other_keys', [])
        authorized_keys = secrets.get('authorized_keys', [])
        known_hosts = secrets.get('known_hosts', [])

        # Only show section if we found something
        if not any([ssh_keys, gpg_keyrings, other_keys, authorized_keys]):
            return ""

        doc = """## SSH Keys & Credentials

"""
        # SSH Private Keys
        if ssh_keys:
            user_keys = [k for k in ssh_keys if not k.get('is_host_key')]
            host_keys = [k for k in ssh_keys if k.get('is_host_key')]

            if user_keys:
                doc += """### User SSH Private Keys

| Path | Type | Owner | Encrypted | Has .pub |
|------|------|-------|-----------|----------|
"""
                for key in user_keys:
                    encrypted = "Yes" if key.get('encrypted') else "**No**"
                    has_pub = "Yes" if key.get('has_public_key') else "No"
                    doc += f"| `{key.get('path', 'N/A')}` | {key.get('type', 'unknown')} | {key.get('owner', 'N/A')} | {encrypted} | {has_pub} |\n"
                doc += "\n"

                # Warning for unencrypted keys
                unencrypted = [k for k in user_keys if not k.get('encrypted')]
                if unencrypted:
                    doc += f"> **Warning:** {len(unencrypted)} private key(s) are not passphrase protected.\n\n"

            if host_keys:
                doc += f"**System Host Keys:** {len(host_keys)} host keys in `/etc/ssh/`\n\n"

        # Authorized Keys
        if authorized_keys:
            doc += """### Authorized Keys (SSH Access)

| User | Keys | Identifiers |
|------|------|-------------|
"""
            for auth in authorized_keys:
                identifiers = ', '.join(auth.get('key_identifiers', [])[:3])
                if len(auth.get('key_identifiers', [])) > 3:
                    identifiers += '...'
                doc += f"| {auth.get('owner', 'N/A')} | {auth.get('key_count', 0)} | {identifiers or 'N/A'} |\n"
            doc += "\n"

        # Known Hosts
        if known_hosts:
            total_hosts = sum(kh.get('host_count', 0) for kh in known_hosts)
            doc += f"**Known Hosts:** {total_hosts} hosts across {len(known_hosts)} user(s)\n\n"

        # GPG Keyrings
        if gpg_keyrings:
            doc += """### GPG Keyrings

| Owner | Path | Public Keys | Secret Keys | Size |
|-------|------|-------------|-------------|------|
"""
            for keyring in gpg_keyrings:
                doc += f"| {keyring.get('owner', 'N/A')} | `{keyring.get('path', 'N/A')}` | {keyring.get('key_count', 0)} | {keyring.get('secret_key_count', 0)} | {keyring.get('size', 'N/A')} |\n"
            doc += "\n"

            # List GPG key identities
            for keyring in gpg_keyrings:
                secret_keys = keyring.get('secret_keys', [])
                if secret_keys:
                    doc += f"**{keyring.get('owner', 'Unknown')}'s GPG Identities:**\n\n"
                    for key in secret_keys[:5]:
                        doc += f"- `{key.get('id', 'N/A')}` - {key.get('uid', 'No UID')}\n"
                    if len(secret_keys) > 5:
                        doc += f"- *...and {len(secret_keys) - 5} more*\n"
                    doc += "\n"

        # Other Keys/Certificates
        private_keys = [k for k in other_keys if k.get('is_private_key')]
        if private_keys:
            doc += """### Other Private Keys/Certificates

| Path | Type |
|------|------|
"""
            for key in private_keys[:10]:
                doc += f"| `{key.get('path', 'N/A')}` | {key.get('type', 'unknown')} |\n"
            if len(private_keys) > 10:
                doc += f"\n*...and {len(private_keys) - 10} more key files*\n"
            doc += "\n"

        return doc

    def _generate_security_assessment(self) -> str:
        """Generate security assessment section"""
        services = self.data.get('processes', {}).get('services', [])
        listening = self.data.get('processes', {}).get('listening_ports', [])
        packages = self.data.get('files', {}).get('installed_packages', [])

        doc = """## Security Assessment

### Quick Security Checklist

"""
        checks = []

        # Get service names handling both Linux and Windows states
        service_names = [s.get('name', '').lower() for s in services
                        if s.get('active') in ['active', 'running'] or s.get('status') in ['running', 'Running']]

        if self.os_type == 'windows':
            # Windows-specific security checks

            # Check for Windows Firewall
            firewall_active = any(fw in service_names for fw in ['mpssvc', 'windows firewall', 'bfe'])
            if firewall_active:
                checks.append(("[OK] Windows Firewall service is running", True))
            else:
                checks.append(("[!!] Windows Firewall not detected - security risk", False))

            # Check for Windows Defender
            defender_active = any(d in service_names for d in ['windefend', 'windows defender', 'msmpeng'])
            if defender_active:
                checks.append(("[OK] Windows Defender is running", True))
            else:
                checks.append(("[--] Windows Defender not detected - ensure alternative AV is installed", False))

            # Check for Remote Desktop
            rdp_active = any('termservice' in s for s in service_names)
            if rdp_active:
                checks.append(("[!!] Remote Desktop Services enabled - ensure NLA is required", False))
            else:
                checks.append(("[OK] Remote Desktop Services not running", True))

            # Check for WinRM
            winrm_active = any('winrm' in s for s in service_names)
            if winrm_active:
                checks.append(("[--] WinRM is enabled - ensure proper authentication is configured", False))

            # Check for exposed risky ports (Windows-specific)
            risky_ports = [21, 23, 445, 1433, 3389, 5985, 5986]
            exposed_risky = [p for p in listening if p.get('port') in risky_ports and p.get('addr') in ['0.0.0.0', '*', '::']]
            if exposed_risky:
                ports_str = ', '.join([str(p.get('port')) for p in exposed_risky])
                checks.append((f"[!!] Sensitive ports exposed: {ports_str} (consider firewall rules)", False))
            else:
                checks.append(("[OK] No sensitive ports exposed publicly", True))

            # Check for Windows Update service
            wuauserv = any('wuauserv' in s for s in service_names)
            if wuauserv:
                checks.append(("[OK] Windows Update service is running", True))
            else:
                checks.append(("[!!] Windows Update service not running - security risk", False))

            # Check for Event Log
            eventlog = any('eventlog' in s for s in service_names)
            if eventlog:
                checks.append(("[OK] Event logging is enabled", True))
            else:
                checks.append(("[!!] Event logging not detected - enable for audit compliance", False))

            # Check for LAPS (if domain-joined, look for LAPS-related services)
            # This is informational since LAPS runs as scheduled tasks

        else:
            # Linux-specific security checks

            # Check for SSH
            ssh_active = any('ssh' in s for s in service_names)
            if ssh_active:
                checks.append(("[OK] SSH service is running for remote access", True))
            else:
                checks.append(("[--] SSH service not detected", False))

            # Check for firewall
            firewall_active = any(fw in service_names for fw in ['ufw', 'firewalld', 'iptables', 'nftables'])
            if firewall_active:
                checks.append(("[OK] Firewall service detected", True))
            else:
                checks.append(("[!!] No firewall service detected - recommend enabling ufw or firewalld", False))

            # Check for exposed risky ports (Linux)
            risky_ports = [21, 23, 25, 3306, 5432, 6379, 27017]
            exposed_risky = [p for p in listening if p.get('port') in risky_ports and p.get('addr') in ['0.0.0.0', '*', '::']]
            if exposed_risky:
                ports_str = ', '.join([str(p.get('port')) for p in exposed_risky])
                checks.append((f"[!!] Sensitive ports exposed publicly: {ports_str}", False))
            else:
                checks.append(("[OK] No sensitive database/service ports exposed publicly", True))

            # Check for fail2ban
            fail2ban = any('fail2ban' in s for s in service_names)
            if fail2ban:
                checks.append(("[OK] fail2ban is running for brute-force protection", True))
            else:
                checks.append(("[--] fail2ban not detected - consider installing for SSH protection", False))

            # Check for automatic updates
            unattended = any('unattended' in p.get('name', '').lower() for p in packages)
            if unattended:
                checks.append(("[OK] Automatic security updates appear to be configured", True))
            else:
                checks.append(("[--] Automatic updates not detected - consider enabling", False))

            # Check for SELinux/AppArmor
            selinux = any('selinux' in s for s in service_names)
            apparmor = any('apparmor' in s for s in service_names)
            if selinux or apparmor:
                checks.append(("[OK] Mandatory Access Control (SELinux/AppArmor) detected", True))
            else:
                checks.append(("[--] No MAC system detected - consider enabling SELinux or AppArmor", False))

        for check, is_good in checks:
            doc += f"- {check}\n"

        doc += "\n"

        # Security score
        good_checks = sum(1 for _, is_good in checks if is_good)
        total_checks = len(checks)
        security_score = int((good_checks / total_checks) * 100) if total_checks > 0 else 0

        doc += f"""### Security Score: {security_score}/100

"""
        if security_score >= 80:
            doc += "> Security posture looks good. Continue monitoring and keep systems updated.\n\n"
        elif security_score >= 50:
            doc += "> Security posture is acceptable but could be improved. Review warnings above.\n\n"
        else:
            doc += "> **Security posture needs attention.** Address the warnings above as soon as possible.\n\n"

        return doc

    def _generate_configuration_section(self) -> str:
        """Generate configuration section"""
        service_configs = self.data.get('files', {}).get('service_configs', {})
        recent = self.data.get('files', {}).get('recently_modified', [])

        doc = """## Configuration

### Service Configuration Paths

"""
        if service_configs:
            for service, configs in service_configs.items():
                if configs:
                    doc += f"**{service.title()}:**\n"
                    for config in configs:
                        doc += f"- `{config.get('path', 'N/A')}`\n"
                    doc += "\n"

        if recent:
            doc += """### Recently Modified Configuration Files

*Files in /etc modified in the last 30 days:*

"""
            doc += "| File | Modified |\n"
            doc += "|------|----------|\n"
            for f in recent[:15]:
                doc += f"| `{f.get('path', 'N/A')}` | {f.get('modified', 'Unknown')} |\n"
            doc += "\n"

        return doc

    def _generate_dependencies_section(self) -> str:
        """Generate dependencies section"""
        packages = self.data.get('files', {}).get('installed_packages', [])
        setup_cmds = self.data.get('history', {}).get('setup_commands', [])

        doc = """## Dependencies & Packages

"""
        if packages:
            by_manager = {}
            for pkg in packages:
                manager = pkg.get('manager', 'unknown')
                if manager not in by_manager:
                    by_manager[manager] = []
                by_manager[manager].append(pkg)

            for manager, pkgs in by_manager.items():
                doc += f"""### {manager.upper()} Packages ({len(pkgs)} total)

<details>
<summary>Click to expand package list</summary>

| Package | Version |
|---------|---------|
"""
                for pkg in sorted(pkgs, key=lambda x: x.get('name', ''))[:100]:
                    doc += f"| {pkg.get('name', 'N/A')} | {pkg.get('version', 'N/A')} |\n"

                if len(pkgs) > 100:
                    doc += f"\n*... and {len(pkgs) - 100} more packages*\n"

                doc += "\n</details>\n\n"

        if setup_cmds:
            doc += """### Setup Commands From History

*These commands were found in bash history and may indicate how this server was configured:*

```bash
"""
            seen = set()
            for cmd in setup_cmds[:25]:
                cmd_str = cmd.get('command', '')
                if cmd_str not in seen:
                    doc += f"{cmd_str}\n"
                    seen.add(cmd_str)
            doc += "```\n\n"

        return doc

    def _generate_recommendations(self) -> str:
        """Generate recommendations section based on analysis"""
        metrics = self.data.get('metrics_analysis', {})
        recommendations = metrics.get('recommendations', [])

        # Generate additional recommendations based on analysis
        additional = []

        # Resource recommendations
        resource = self.data.get('processes', {}).get('resource_usage', {})
        memory = resource.get('memory', {})
        mem_percent = memory.get('percent', 0)

        if mem_percent > 80:
            additional.append("Consider adding more RAM or identifying memory-hungry processes")
        elif mem_percent < 30:
            additional.append("This server may be overprovisioned - consider downsizing to save costs")

        # Service recommendations
        services = self.data.get('processes', {}).get('services', [])
        service_names = [s.get('name', '').lower() for s in services]

        if 'nginx' in service_names and 'apache2' in service_names:
            additional.append("Both nginx and Apache are installed - consider consolidating to one web server")

        all_recommendations = recommendations + additional

        if not all_recommendations:
            return ""

        doc = """## Recommendations

Based on the analysis, here are our recommendations:

"""
        for i, rec in enumerate(all_recommendations, 1):
            doc += f"{i}. {rec}\n"

        doc += "\n"
        return doc

    def _generate_scaling_section(self) -> str:
        """Generate scaling recommendations based on current workload"""
        resource = self.data.get('processes', {}).get('resource_usage', {})
        services = self.data.get('processes', {}).get('services', [])
        processes = self.data.get('processes', {}).get('running', [])
        metrics = self.data.get('metrics_analysis', {})
        summary = metrics.get('metrics_summary', {})

        cpu = resource.get('cpu', {})
        memory = resource.get('memory', {})

        doc = """## Scaling Recommendations

### Current Capacity Analysis

"""
        cpu_count = cpu.get('count', 1)
        total_mem_gb = round(memory.get('total', 0) / 1024 / 1024 / 1024, 1)
        mem_percent = memory.get('percent', 0)
        cpu_avg = summary.get('cpu_avg', 0) if summary else 0

        # Determine service types for scaling advice
        service_names = [s.get('name', '').lower() for s in services]
        process_names = [p.get('name', '').lower() for p in processes]

        is_web_server = any(w in service_names + process_names for w in ['nginx', 'apache2', 'httpd'])
        is_database = any(d in service_names + process_names for d in ['mysql', 'postgresql', 'mongodb', 'redis'])
        is_container_host = any(c in service_names + process_names for c in ['docker', 'containerd'])
        is_stateless_app = any(a in service_names + process_names for a in ['node', 'python', 'java', 'go', 'ruby'])

        doc += f"""| Current Specs | Value | Utilization |
|---------------|-------|-------------|
| CPU Cores | {cpu_count} | {cpu_avg:.1f}% avg |
| Memory | {total_mem_gb} GB | {mem_percent}% used |

"""

        # Horizontal vs Vertical scaling advice
        doc += """### Scaling Strategy

"""
        if is_web_server or is_stateless_app:
            doc += """**Horizontal Scaling Recommended**

This server runs stateless services that can scale horizontally:

1. **Load Balancer Setup**
   - Deploy a load balancer (HAProxy, nginx, or cloud LB)
   - Add additional server instances behind the LB
   - Use sticky sessions only if absolutely necessary

2. **Auto-Scaling Considerations**
   - Metrics to monitor: CPU usage, request latency, queue depth
   - Scale out at 70% CPU utilization
   - Scale in at 30% CPU utilization with cooldown period
   - Consider time-based scaling for predictable traffic patterns

3. **Session Management**
   - Move sessions to Redis/Memcached for shared state
   - Use JWT tokens for stateless authentication
   - Implement health check endpoints

"""
        if is_database:
            doc += """**Database Scaling Strategy**

This server runs database services that require careful scaling:

1. **Vertical Scaling (Recommended First)**
   - Increase memory for larger cache/buffer pools
   - Add CPU cores for query parallelization
   - Use faster storage (NVMe SSD)

2. **Read Scaling**
   - Set up read replicas for SELECT-heavy workloads
   - Use connection pooling (PgBouncer, ProxySQL)
   - Implement query result caching

3. **Write Scaling (Advanced)**
   - Consider sharding for write-heavy workloads
   - Evaluate partitioning tables by date/region
   - Use async replication for geo-distribution

"""
        if is_container_host:
            doc += """**Container Orchestration Scaling**

Consider migrating to Kubernetes or Docker Swarm for:

1. **Container Orchestration Benefits**
   - Automatic container scheduling and placement
   - Built-in service discovery and load balancing
   - Rolling deployments with zero downtime
   - Horizontal Pod Autoscaler for demand-based scaling

2. **Resource Requests/Limits**
   - Set CPU/memory requests for guaranteed resources
   - Set limits to prevent resource hogging
   - Use resource quotas per namespace

"""

        # Capacity planning
        doc += """### Capacity Planning

"""
        if mem_percent > 70:
            doc += f"""**Memory Pressure Detected** ({mem_percent}% used)

- **Immediate:** Add {round(total_mem_gb * 0.5)} GB more RAM
- **Consider:** Increasing to {round(total_mem_gb * 2)} GB for growth headroom
- **Action:** Identify and optimize memory-hungry processes

"""
        elif mem_percent < 40:
            doc += f"""**Memory Underutilized** ({mem_percent}% used)

- Current allocation may be excessive
- Could downsize to {max(1, round(total_mem_gb * 0.6))} GB to save costs
- Monitor for 1-2 weeks to confirm usage patterns

"""

        if cpu_avg > 60:
            doc += f"""**CPU Utilization High** ({cpu_avg:.1f}% average)

- Add {cpu_count} more cores (total: {cpu_count * 2})
- Or scale horizontally with additional instances
- Profile application for optimization opportunities

"""
        elif cpu_avg < 20:
            doc += f"""**CPU Underutilized** ({cpu_avg:.1f}% average)

- Could reduce to {max(1, cpu_count // 2)} cores
- Or consolidate workloads from other servers
- Good candidate for containerization

"""

        return doc

    def _generate_containerization_section(self) -> str:
        """Generate containerization suggestions based on running services"""
        services = self.data.get('processes', {}).get('services', [])
        processes = self.data.get('processes', {}).get('running', [])
        packages = self.data.get('files', {}).get('installed_packages', [])
        history = self.data.get('history', {}).get('setup_commands', [])

        service_names = [s.get('name', '').lower() for s in services if s.get('active') == 'active']
        process_names = [p.get('name', '').lower() for p in processes]
        package_names = [p.get('name', '').lower() for p in packages]

        # Check if already containerized
        is_containerized = any(c in service_names + process_names for c in ['docker', 'containerd', 'podman'])

        doc = """## Containerization Suggestions

"""
        if is_containerized:
            doc += """> This server already runs containers. Suggestions below are for optimizing your container setup.

"""

        # Identify containerizable services
        containerizable = []

        web_services = {
            'nginx': {'base': 'nginx:alpine', 'port': 80, 'notes': 'Excellent for containerization'},
            'apache2': {'base': 'httpd:alpine', 'port': 80, 'notes': 'Consider switching to nginx'},
            'caddy': {'base': 'caddy:alpine', 'port': 80, 'notes': 'Great auto-HTTPS support'},
        }

        db_services = {
            'mysql': {'base': 'mysql:8', 'port': 3306, 'notes': 'Use named volumes for data persistence'},
            'mariadb': {'base': 'mariadb:10', 'port': 3306, 'notes': 'MySQL-compatible, lighter weight'},
            'postgresql': {'base': 'postgres:15-alpine', 'port': 5432, 'notes': 'Production-ready image available'},
            'mongodb': {'base': 'mongo:6', 'port': 27017, 'notes': 'Use replica sets for production'},
            'redis': {'base': 'redis:alpine', 'port': 6379, 'notes': 'Perfect for containerization'},
        }

        app_services = {
            'node': {'base': 'node:20-alpine', 'notes': 'Multi-stage build recommended'},
            'python': {'base': 'python:3.11-slim', 'notes': 'Use slim or alpine variants'},
            'java': {'base': 'eclipse-temurin:17-jre-alpine', 'notes': 'Use JRE image for runtime'},
            'php': {'base': 'php:8.2-fpm-alpine', 'notes': 'Combine with nginx for best results'},
        }

        for name, config in web_services.items():
            if name in service_names or name in process_names:
                containerizable.append({
                    'service': name,
                    'type': 'Web Server',
                    **config
                })

        for name, config in db_services.items():
            if name in service_names or name in process_names:
                containerizable.append({
                    'service': name,
                    'type': 'Database',
                    **config
                })

        for name, config in app_services.items():
            if name in process_names or any(name in p for p in package_names):
                containerizable.append({
                    'service': name,
                    'type': 'Application Runtime',
                    **config
                })

        if containerizable:
            doc += """### Services Suitable for Containerization

| Service | Type | Base Image | Notes |
|---------|------|------------|-------|
"""
            for svc in containerizable:
                base = svc.get('base', 'N/A')
                doc += f"| {svc['service']} | {svc['type']} | `{base}` | {svc.get('notes', '')} |\n"
            doc += "\n"

        # Docker Compose suggestion
        if len(containerizable) >= 2:
            doc += """### Suggested Docker Compose Structure

Based on detected services, here's a recommended structure:

```yaml
version: '3.8'

services:
"""
            for svc in containerizable[:4]:
                service_name = svc['service']
                base_image = svc.get('base', 'alpine')
                port = svc.get('port', 8080)

                doc += f"""  {service_name}:
    image: {base_image}
    restart: unless-stopped
"""
                if port:
                    doc += f"""    ports:
      - "{port}:{port}"
"""
                if svc['type'] == 'Database':
                    doc += f"""    volumes:
      - {service_name}_data:/var/lib/{service_name}
    environment:
      - {service_name.upper()}_ROOT_PASSWORD=${{DB_PASSWORD}}

"""
                else:
                    doc += "\n"

            # Add volumes section for databases
            db_svcs = [s for s in containerizable if s['type'] == 'Database']
            if db_svcs:
                doc += """volumes:
"""
                for svc in db_svcs:
                    doc += f"  {svc['service']}_data:\n"

            doc += "```\n\n"

        # Migration steps
        doc += """### Container Migration Steps

1. **Audit Dependencies**
   - Document all installed packages
   - Identify configuration files to mount
   - List environment variables needed

2. **Create Dockerfile**
   - Start with official base images
   - Use multi-stage builds for compiled languages
   - Keep images minimal (alpine variants)

3. **Data Management**
   - Use named volumes for persistent data
   - Set up backup procedures for volumes
   - Test data restore procedures

4. **Network Configuration**
   - Create dedicated Docker networks
   - Use service names for inter-container communication
   - Expose only necessary ports to host

5. **Orchestration Decision**
   - Single server: Docker Compose is sufficient
   - Multiple servers: Consider Docker Swarm or Kubernetes
   - Cloud deployment: Use managed container services (ECS, GKE, AKS)

"""

        # Benefits/considerations
        doc += """### Benefits vs Trade-offs

| Benefits | Trade-offs |
|----------|------------|
| Consistent environments | Learning curve for team |
| Easy horizontal scaling | Additional abstraction layer |
| Simplified deployments | Storage complexity for DBs |
| Better resource isolation | Networking complexity |
| Version-controlled infrastructure | Monitoring overhead |

"""
        return doc

    def _generate_config_improvements_section(self) -> str:
        """Generate configuration improvement suggestions"""
        services = self.data.get('processes', {}).get('services', [])
        processes = self.data.get('processes', {}).get('running', [])
        packages = self.data.get('files', {}).get('installed_packages', [])
        resource = self.data.get('processes', {}).get('resource_usage', {})
        service_configs = self.data.get('files', {}).get('service_configs', {})
        listening = self.data.get('processes', {}).get('listening_ports', [])
        secrets = self.data.get('secrets', {})

        service_names = [s.get('name', '').lower() for s in services if s.get('active') == 'active']
        process_names = [p.get('name', '').lower() for p in processes]
        package_names = [p.get('name', '').lower() for p in packages]

        memory = resource.get('memory', {})
        total_mem_gb = memory.get('total', 0) / 1024 / 1024 / 1024

        doc = """## Configuration Improvement Suggestions

"""
        improvements = []

        # Web server improvements
        if 'nginx' in service_names or 'nginx' in process_names:
            improvements.append({
                'service': 'nginx',
                'category': 'Web Server',
                'suggestions': [
                    'Enable gzip compression for text responses',
                    'Configure worker_processes to match CPU cores',
                    'Set up connection keep-alive timeouts',
                    'Enable HTTP/2 for HTTPS connections',
                    'Configure proper buffer sizes based on content type',
                    'Implement rate limiting for DDoS protection'
                ],
                'config_snippet': '''# nginx.conf optimization
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Compression
    gzip on;
    gzip_comp_level 5;
    gzip_types text/plain application/json application/javascript text/css;

    # Timeouts
    keepalive_timeout 65;
    client_body_timeout 12;
    send_timeout 10;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}'''
            })

        # MySQL/MariaDB improvements
        if any(db in service_names + process_names for db in ['mysql', 'mariadb']):
            buffer_pool_size = max(1, int(total_mem_gb * 0.7))
            improvements.append({
                'service': 'MySQL/MariaDB',
                'category': 'Database',
                'suggestions': [
                    f'Set innodb_buffer_pool_size to {buffer_pool_size}G (70% of RAM)',
                    'Enable slow query log for performance debugging',
                    'Configure query cache appropriately (or disable for MySQL 8+)',
                    'Set appropriate max_connections for your workload',
                    'Enable binary logging for point-in-time recovery',
                    'Use connection pooling to reduce connection overhead'
                ],
                'config_snippet': f'''# my.cnf optimization
[mysqld]
# InnoDB settings
innodb_buffer_pool_size = {buffer_pool_size}G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT

# Query performance
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Connection handling
max_connections = 200
wait_timeout = 300'''
            })

        # PostgreSQL improvements
        if 'postgresql' in service_names or 'postgres' in process_names:
            shared_buffers = max(256, int(total_mem_gb * 0.25 * 1024))  # MB
            effective_cache = max(1, int(total_mem_gb * 0.75))
            improvements.append({
                'service': 'PostgreSQL',
                'category': 'Database',
                'suggestions': [
                    f'Set shared_buffers to {shared_buffers}MB (25% of RAM)',
                    f'Set effective_cache_size to {effective_cache}GB (75% of RAM)',
                    'Enable pg_stat_statements for query analysis',
                    'Configure appropriate work_mem for complex queries',
                    'Set up streaming replication for HA',
                    'Use pgBouncer for connection pooling'
                ],
                'config_snippet': f'''# postgresql.conf optimization
# Memory settings
shared_buffers = {shared_buffers}MB
effective_cache_size = {effective_cache}GB
work_mem = 64MB
maintenance_work_mem = 512MB

# WAL settings
wal_buffers = 64MB
checkpoint_completion_target = 0.9

# Logging
log_min_duration_statement = 1000
log_checkpoints = on'''
            })

        # Redis improvements
        if 'redis' in service_names or 'redis' in process_names:
            max_memory = max(1, int(total_mem_gb * 0.5))
            improvements.append({
                'service': 'Redis',
                'category': 'Cache/Store',
                'suggestions': [
                    f'Set maxmemory to {max_memory}G with eviction policy',
                    'Enable RDB snapshots for persistence',
                    'Consider AOF for durability requirements',
                    'Disable KEYS command in production',
                    'Set appropriate timeout for idle connections',
                    'Use Redis Cluster for horizontal scaling'
                ],
                'config_snippet': f'''# redis.conf optimization
maxmemory {max_memory}gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
appendonly yes
appendfsync everysec

# Security
rename-command FLUSHALL ""
rename-command KEYS ""
timeout 300'''
            })

        # Docker improvements
        if 'docker' in service_names or 'docker' in process_names:
            improvements.append({
                'service': 'Docker',
                'category': 'Container Runtime',
                'suggestions': [
                    'Enable live restore for daemon restarts',
                    'Configure log rotation to prevent disk fill',
                    'Use overlay2 storage driver',
                    'Set default ulimits for containers',
                    'Enable user namespaces for security',
                    'Configure prune policies for old images'
                ],
                'config_snippet': '''{
  "live-restore": true,
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65535,
      "Soft": 65535
    }
  }
}'''
            })

        # SSH improvements
        ssh_keys = secrets.get('ssh_keys', [])
        unencrypted_keys = [k for k in ssh_keys if not k.get('encrypted') and not k.get('is_host_key')]
        if 'ssh' in service_names or 'sshd' in service_names:
            suggestions = [
                'Disable password authentication, use keys only',
                'Disable root login via SSH',
                'Use fail2ban for brute-force protection',
                'Change default port (security through obscurity)',
                'Enable two-factor authentication'
            ]
            if unencrypted_keys:
                suggestions.insert(0, f'**URGENT**: Encrypt {len(unencrypted_keys)} unprotected SSH private keys')

            improvements.append({
                'service': 'SSH',
                'category': 'Security',
                'suggestions': suggestions,
                'config_snippet': '''# sshd_config hardening
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no'''
            })

        # ===================
        # WINDOWS-SPECIFIC IMPROVEMENTS
        # ===================

        # IIS Web Server improvements
        if any(iis in service_names + process_names for iis in ['w3svc', 'iisadmin', 'w3wp']):
            improvements.append({
                'service': 'IIS',
                'category': 'Web Server',
                'suggestions': [
                    'Enable dynamic and static compression',
                    'Configure application pool recycling schedule',
                    'Set idle timeout for application pools',
                    'Enable HTTP/2 for improved performance',
                    'Configure request filtering and URL rewrite rules',
                    'Implement output caching for static content',
                    'Enable Failed Request Tracing for debugging'
                ],
                'config_snippet': '''<!-- web.config optimization -->
<system.webServer>
  <httpCompression>
    <dynamicTypes>
      <add mimeType="application/json" enabled="true"/>
    </dynamicTypes>
  </httpCompression>
  <urlCompression doStaticCompression="true" doDynamicCompression="true"/>
  <security>
    <requestFiltering>
      <requestLimits maxAllowedContentLength="30000000"/>
    </requestFiltering>
  </security>
  <httpProtocol>
    <customHeaders>
      <add name="X-Content-Type-Options" value="nosniff"/>
      <add name="X-Frame-Options" value="SAMEORIGIN"/>
    </customHeaders>
  </httpProtocol>
</system.webServer>'''
            })

        # SQL Server improvements
        if any(sql in service_names + process_names for sql in ['mssqlserver', 'sqlservr', 'mssql']):
            buffer_pool_mb = max(1024, int(total_mem_gb * 0.75 * 1024))
            improvements.append({
                'service': 'SQL Server',
                'category': 'Database',
                'suggestions': [
                    f'Set max server memory to {buffer_pool_mb}MB (75% of RAM)',
                    'Enable instant file initialization for faster restores',
                    'Configure TempDB with multiple data files (1 per CPU core, up to 8)',
                    'Enable Query Store for performance insights',
                    'Set cost threshold for parallelism (recommend 50)',
                    'Configure backup compression by default',
                    'Enable transparent data encryption (TDE) for security',
                    'Set up database mail for alerts'
                ],
                'config_snippet': f'''-- SQL Server optimization
EXEC sp_configure 'max server memory', {buffer_pool_mb};
EXEC sp_configure 'cost threshold for parallelism', 50;
EXEC sp_configure 'max degree of parallelism', 4;
EXEC sp_configure 'backup compression default', 1;
RECONFIGURE;

-- Enable Query Store on databases
ALTER DATABASE [YourDB] SET QUERY_STORE = ON;

-- TempDB optimization (run and restart)
ALTER DATABASE tempdb ADD FILE (NAME = tempdev2, FILENAME = 'T:\\TempDB\\tempdb2.ndf', SIZE = 1024MB);'''
            })

        # Hyper-V improvements
        if any(hv in service_names + process_names for hv in ['vmms', 'vmcompute', 'vmwp']):
            improvements.append({
                'service': 'Hyper-V',
                'category': 'Virtualization',
                'suggestions': [
                    'Use Generation 2 VMs for UEFI and better performance',
                    'Enable Secure Boot on VMs where possible',
                    'Configure dynamic memory with appropriate min/max',
                    'Use fixed-size VHDXs for production workloads',
                    'Enable SR-IOV for network-intensive VMs',
                    'Configure VM checkpoints sparingly in production',
                    'Use Cluster Shared Volumes for HA deployments',
                    'Enable Replica for disaster recovery'
                ],
                'config_snippet': '''# PowerShell Hyper-V optimization
# Set VM memory
Set-VMMemory -VMName "VM1" -DynamicMemoryEnabled $true -MinimumBytes 2GB -MaximumBytes 8GB

# Enable virtual TPM for Secure Boot
Set-VMSecurity -VMName "VM1" -VirtualizationBasedSecurityOptOut $false
Enable-VMTPM -VMName "VM1"

# Configure high availability
Enable-VMReplication -VMName "VM1" -ReplicaServerName "HVReplica01" -ReplicaServerPort 443'''
            })

        # Veeam Backup improvements
        if any(v in name for name in service_names + process_names for v in ['veeam', 'veeambackup']):
            improvements.append({
                'service': 'Veeam Backup',
                'category': 'Backup & DR',
                'suggestions': [
                    'Configure backup copy jobs for 3-2-1 rule compliance',
                    'Enable GFS (Grandfather-Father-Son) retention policy',
                    'Use incremental backup with periodic synthetic fulls',
                    'Configure backup I/O control to prevent production impact',
                    'Enable encryption for backup files and traffic',
                    'Set up SureBackup for automated recovery testing',
                    'Configure email notifications and SNMP monitoring',
                    'Use WAN accelerators for remote backup copy jobs'
                ],
                'config_snippet': '''# Veeam Best Practices
# - Use ReFS for backup repository (block cloning support)
# - Allocate 1 CPU core per 3 concurrent tasks
# - Reserve 4GB RAM + 500MB per concurrent task
# - Use fast storage for backup proxy
# - Enable CBT (Changed Block Tracking) on VMware VMs
# - Schedule synthetic fulls during maintenance windows'''
            })

        # Active Directory improvements
        if any(ad in service_names for ad in ['ntds', 'adws', 'kdc']):
            improvements.append({
                'service': 'Active Directory',
                'category': 'Identity',
                'suggestions': [
                    'Enable AD Recycle Bin for object recovery',
                    'Configure fine-grained password policies',
                    'Enable Protected Users security group',
                    'Implement LAPS for local admin passwords',
                    'Configure audit policies for security monitoring',
                    'Set up Azure AD Connect for hybrid identity',
                    'Enable Credential Guard on DCs',
                    'Regular DCDIAG and repadmin health checks'
                ],
                'config_snippet': '''# PowerShell AD hardening
# Enable Recycle Bin (forest-wide, one-time)
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name

# Enable advanced audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "AdminUser"'''
            })

        # Windows Server general hardening
        if self.os_type == 'windows' and not improvements:
            improvements.append({
                'service': 'Windows Server',
                'category': 'Security Hardening',
                'suggestions': [
                    'Apply CIS Benchmark or STIG hardening',
                    'Enable Windows Defender Credential Guard',
                    'Configure Windows Firewall with Advanced Security',
                    'Enable PowerShell script block logging',
                    'Disable SMBv1 protocol',
                    'Configure NTP for accurate time sync',
                    'Enable BitLocker for drive encryption',
                    'Configure Windows Event Forwarding for centralized logging'
                ],
                'config_snippet': '''# PowerShell hardening commands
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Enable PowerShell logging
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Configure Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable audit logging
auditpol /set /category:"Account Logon" /success:enable /failure:enable'''
            })

        # Output the improvements
        if improvements:
            for imp in improvements:
                doc += f"""### {imp['service']} ({imp['category']})

**Recommended Improvements:**

"""
                for i, suggestion in enumerate(imp['suggestions'], 1):
                    doc += f"{i}. {suggestion}\n"

                doc += f"""

<details>
<summary>Example Configuration</summary>

```
{imp['config_snippet']}
```

</details>

"""

        # General system improvements
        doc += """### General System Improvements

"""
        general_improvements = []

        # Check for swap
        swap_total = resource.get('memory', {}).get('swap_total', 0)
        if swap_total == 0:
            general_improvements.append("Configure swap space (recommended: equal to RAM up to 8GB)")

        # Check for open file limits
        general_improvements.append("Increase system file descriptor limits for high-traffic services")
        general_improvements.append("Configure proper sysctl parameters for network performance")
        general_improvements.append("Set up centralized logging (ELK, Loki, or cloud logging)")
        general_improvements.append("Implement proper backup strategy with offsite copies")
        general_improvements.append("Configure monitoring and alerting (Prometheus + Grafana)")

        for i, imp in enumerate(general_improvements, 1):
            doc += f"{i}. {imp}\n"

        doc += """

### Sysctl Tuning for High Performance

```bash
# /etc/sysctl.conf additions for network optimization
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
vm.swappiness = 10
fs.file-max = 2097152
```

"""
        return doc

    def _generate_footer(self) -> str:
        """Generate document footer"""
        process_count = len(self.data.get('processes', {}).get('running', []))
        service_count = len(self.data.get('processes', {}).get('services', []))
        package_count = len(self.data.get('files', {}).get('installed_packages', []))

        return f"""---

<div align="center">

### Analysis Metadata

| Metric | Value |
|--------|-------|
| Hostname | `{self.hostname}` |
| Analysis Date | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
| Processes Analyzed | {process_count} |
| Services Found | {service_count} |
| Packages Detected | {package_count} |

---

*Generated by [What Does This Box Do?](https://github.com/whatdoesthisboxdo)*

</div>
"""
