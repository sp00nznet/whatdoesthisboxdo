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

    def generate(self, output_path: str) -> str:
        """Generate full documentation"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)

        doc = self._generate_header()
        doc += self._generate_executive_summary()
        doc += self._generate_system_identity()
        doc += self._generate_health_assessment()
        doc += self._generate_metrics_section()
        doc += self._generate_services_section()
        doc += self._generate_network_section()
        doc += self._generate_storage_section()
        doc += self._generate_security_assessment()
        doc += self._generate_configuration_section()
        doc += self._generate_dependencies_section()
        doc += self._generate_recommendations()
        doc += self._generate_troubleshooting_section()
        doc += self._generate_footer()

        with open(output_path, 'w') as f:
            f.write(doc)

        logger.info(f"Documentation generated: {output_path}")
        return output_path

    def _generate_header(self) -> str:
        """Generate beautiful document header"""
        os_name = self.os_info.get('distro', 'Linux')
        os_version = self.os_info.get('version', '')

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

        service_names = [s.get('name', '').lower() for s in services if s.get('active') == 'active']
        process_names = [p.get('name', '').lower() for p in processes]
        package_names = [p.get('name', '').lower() for p in packages]
        port_numbers = [p.get('port', 0) for p in ports]

        roles = []

        # Web Server Detection
        web_indicators = ['nginx', 'apache2', 'httpd', 'caddy', 'lighttpd']
        if any(w in service_names or w in process_names for w in web_indicators):
            roles.append(('Web Server', 0.9, 'Serves HTTP/HTTPS traffic to clients'))

        # Database Detection
        db_indicators = {
            'mysql': 'MySQL relational database',
            'mariadb': 'MariaDB relational database',
            'postgresql': 'PostgreSQL relational database',
            'mongodb': 'MongoDB document database',
            'redis': 'Redis in-memory data store',
            'elasticsearch': 'Elasticsearch search engine',
        }
        for db, desc in db_indicators.items():
            if db in service_names or db in process_names:
                roles.append(('Database Server', 0.9, f'Runs {desc}'))

        # Container/Orchestration Detection
        if 'docker' in service_names or 'containerd' in process_names:
            if 'kubelet' in service_names or 'k3s' in process_names:
                roles.append(('Kubernetes Node', 0.9, 'Part of a Kubernetes cluster'))
            else:
                roles.append(('Container Host', 0.85, 'Runs containerized applications via Docker'))

        # CI/CD Detection
        ci_indicators = ['gitlab-runner', 'jenkins', 'drone', 'buildkite']
        if any(ci in service_names or ci in process_names for ci in ci_indicators):
            roles.append(('CI/CD Runner', 0.85, 'Executes continuous integration/deployment pipelines'))

        # Monitoring Detection
        mon_indicators = ['prometheus', 'grafana', 'zabbix', 'nagios', 'influxdb']
        if any(m in service_names or m in process_names for m in mon_indicators):
            roles.append(('Monitoring Server', 0.8, 'Collects and visualizes system metrics'))

        # Mail Server Detection
        if any(m in service_names for m in ['postfix', 'dovecot', 'exim', 'sendmail']):
            roles.append(('Mail Server', 0.85, 'Handles email sending/receiving'))

        # File Server Detection
        if any(f in service_names for f in ['smbd', 'nfs-server', 'vsftpd', 'proftpd']):
            roles.append(('File Server', 0.8, 'Provides file sharing services'))

        # Load Balancer Detection
        if any(lb in service_names or lb in process_names for lb in ['haproxy', 'traefik']):
            roles.append(('Load Balancer', 0.85, 'Distributes traffic across backend servers'))

        # VPN/Gateway Detection
        if any(v in service_names for v in ['openvpn', 'wireguard', 'strongswan']):
            roles.append(('VPN Gateway', 0.8, 'Provides secure network access'))

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
            'nginx': 'Reverse proxy / Web server',
            'apache2': 'Web server',
            'mysql': 'Primary database',
            'postgresql': 'Primary database',
            'redis': 'Caching / Session store',
            'docker': 'Container runtime',
            'sshd': 'Remote access',
            'cron': 'Scheduled tasks',
            'systemd': 'System init',
            'prometheus': 'Metrics collection',
            'grafana': 'Metrics visualization',
            'haproxy': 'Load balancing',
            'postfix': 'Mail delivery',
        }
        return significance_map.get(service_name.lower(), 'System service')

    def _generate_system_identity(self) -> str:
        """Generate system identity section"""
        resource = self.data.get('processes', {}).get('resource_usage', {})
        cpu = resource.get('cpu', {})
        memory = resource.get('memory', {})

        total_mem_gb = round(memory.get('total', 0) / 1024 / 1024 / 1024, 1)
        cpu_count = cpu.get('count', 'N/A')

        doc = """## System Identity

"""
        doc += f"""```
+{'='*60}+
|  HOSTNAME: {self.hostname:<47} |
+{'='*60}+
|  OS: {self.os_info.get('distro', 'Unknown'):<52} |
|  Version: {self.os_info.get('version', 'Unknown'):<47} |
|  Kernel: {self.os_info.get('kernel', 'Unknown'):<48} |
+{'-'*60}+
|  CPUs: {str(cpu_count):<53} |
|  Memory: {str(total_mem_gb) + ' GB':<51} |
+{'='*60}+
```

"""
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

    def _generate_security_assessment(self) -> str:
        """Generate security assessment section"""
        services = self.data.get('processes', {}).get('services', [])
        listening = self.data.get('processes', {}).get('listening_ports', [])
        packages = self.data.get('files', {}).get('installed_packages', [])

        doc = """## Security Assessment

### Quick Security Checklist

"""
        checks = []

        # Check for SSH
        ssh_active = any('ssh' in s.get('name', '').lower() for s in services if s.get('active') == 'active')
        if ssh_active:
            checks.append(("[OK] SSH service is running for remote access", True))
        else:
            checks.append(("[--] SSH service not detected", False))

        # Check for firewall
        firewall_active = any(fw in [s.get('name', '').lower() for s in services] for fw in ['ufw', 'firewalld', 'iptables'])
        if firewall_active:
            checks.append(("[OK] Firewall service detected", True))
        else:
            checks.append(("[!!] No firewall service detected - recommend enabling ufw or firewalld", False))

        # Check for exposed risky ports
        risky_ports = [21, 23, 25, 3306, 5432, 6379, 27017]
        exposed_risky = [p for p in listening if p.get('port') in risky_ports and p.get('addr') in ['0.0.0.0', '*', '::']]
        if exposed_risky:
            ports_str = ', '.join([str(p.get('port')) for p in exposed_risky])
            checks.append((f"[!!] Sensitive ports exposed publicly: {ports_str}", False))
        else:
            checks.append(("[OK] No sensitive database/service ports exposed publicly", True))

        # Check for fail2ban
        fail2ban = any('fail2ban' in s.get('name', '').lower() for s in services)
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

    def _generate_troubleshooting_section(self) -> str:
        """Generate troubleshooting section"""
        role = self._determine_server_role()

        doc = """## Troubleshooting Guide

### Common Commands

"""
        doc += """```bash
# Check system resources
htop                          # Interactive process viewer
free -h                       # Memory usage
df -h                         # Disk usage
iostat -x 1                   # I/O statistics

# Check logs
journalctl -xe                # Recent system logs
journalctl -u <service>       # Service-specific logs
tail -f /var/log/syslog       # Live system log

# Network diagnostics
ss -tuln                      # Listening ports
netstat -an                   # All connections
tcpdump -i any port <port>    # Packet capture
```

"""
        # Role-specific troubleshooting
        role_type = role.get('role_type', '')

        if 'Web Server' in role_type:
            doc += """### Web Server Troubleshooting

```bash
# Nginx
nginx -t                      # Test configuration
systemctl status nginx        # Service status
tail -f /var/log/nginx/error.log

# Apache
apache2ctl configtest
systemctl status apache2
tail -f /var/log/apache2/error.log
```

"""

        if 'Database' in role_type:
            doc += """### Database Troubleshooting

```bash
# MySQL/MariaDB
mysqladmin status
SHOW PROCESSLIST;             # In MySQL shell
tail -f /var/log/mysql/error.log

# PostgreSQL
pg_isready
SELECT * FROM pg_stat_activity;  # In psql
tail -f /var/log/postgresql/postgresql-*-main.log
```

"""

        if 'Container' in role_type or 'Docker' in role_type:
            doc += """### Container Troubleshooting

```bash
docker ps -a                  # All containers
docker logs <container>       # Container logs
docker stats                  # Resource usage
docker system df              # Disk usage
docker inspect <container>    # Full container details
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
