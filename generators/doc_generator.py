"""
Documentation Generator
Generates detailed documentation about the analyzed system
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class DocumentationGenerator:
    """Generates comprehensive system documentation"""

    def __init__(self, analysis_data: Dict[str, Any]):
        self.data = analysis_data
        self.hostname = analysis_data.get('hostname', 'unknown')

    def generate(self, output_path: str) -> str:
        """Generate full documentation"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)

        doc = self._generate_header()
        doc += self._generate_overview()
        doc += self._generate_services_section()
        doc += self._generate_processes_section()
        doc += self._generate_network_section()
        doc += self._generate_storage_section()
        doc += self._generate_configuration_section()
        doc += self._generate_dependencies_section()
        doc += self._generate_troubleshooting_section()
        doc += self._generate_footer()

        with open(output_path, 'w') as f:
            f.write(doc)

        logger.info(f"Documentation generated: {output_path}")
        return output_path

    def _generate_header(self) -> str:
        """Generate document header"""
        return f"""# System Documentation: {self.hostname}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Analysis Tool:** System Analyzer

---

"""

    def _generate_overview(self) -> str:
        """Generate system overview section"""
        summary = self.data.get('summary', {})

        doc = """## System Overview

### Server Purpose
"""
        doc += f"{summary.get('server_purpose', 'Unable to determine server purpose')}\n\n"

        # Resource usage
        resource = self.data.get('processes', {}).get('resource_usage', {})
        if resource:
            cpu = resource.get('cpu', {})
            memory = resource.get('memory', {})

            doc += "### Resource Summary\n\n"
            doc += "| Resource | Value |\n"
            doc += "|----------|-------|\n"

            if cpu:
                doc += f"| CPU Cores | {cpu.get('count', 'N/A')} |\n"
                doc += f"| CPU Usage | {cpu.get('percent', 'N/A')}% |\n"
                load_avg = cpu.get('load_avg', [])
                if load_avg:
                    doc += f"| Load Average | {', '.join(map(str, load_avg))} |\n"

            if memory:
                total_gb = round(memory.get('total', 0) / 1024 / 1024 / 1024, 2)
                used_gb = round(memory.get('used', 0) / 1024 / 1024 / 1024, 2)
                doc += f"| Total Memory | {total_gb} GB |\n"
                doc += f"| Used Memory | {used_gb} GB ({memory.get('percent', 0)}%) |\n"

            doc += "\n"

        return doc

    def _generate_services_section(self) -> str:
        """Generate services section"""
        doc = "## Running Services\n\n"

        services = self.data.get('processes', {}).get('services', [])
        key_services = self.data.get('summary', {}).get('key_services', [])

        if services:
            doc += "### Active Services\n\n"
            doc += "| Service | Status | Description |\n"
            doc += "|---------|--------|-------------|\n"

            for svc in services[:30]:  # Limit to 30
                if svc.get('active') == 'active':
                    doc += f"| {svc.get('name', 'N/A')} | {svc.get('status', 'N/A')} | {svc.get('description', '')[:50]} |\n"

            doc += "\n"

        # Key services with more detail
        if key_services:
            doc += "### Key Services Detail\n\n"
            for svc in key_services:
                doc += f"#### {svc.get('name', 'Unknown')}\n"
                doc += f"- **Status:** {svc.get('status', 'Unknown')}\n"
                if svc.get('ports'):
                    doc += f"- **Ports:** {', '.join(map(str, svc.get('ports', [])))}\n"
                doc += "\n"

        return doc

    def _generate_processes_section(self) -> str:
        """Generate processes section"""
        doc = "## Running Processes\n\n"

        processes = self.data.get('processes', {}).get('running', [])

        if processes:
            # Sort by CPU usage
            sorted_procs = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)

            doc += "### Top Processes by CPU\n\n"
            doc += "| Process | User | CPU % | Memory % | Command |\n"
            doc += "|---------|------|-------|----------|--------|\n"

            for proc in sorted_procs[:15]:
                cmdline = proc.get('cmdline', proc.get('name', 'N/A'))
                if len(cmdline) > 50:
                    cmdline = cmdline[:47] + "..."
                doc += f"| {proc.get('name', 'N/A')} | {proc.get('user', 'N/A')} | {proc.get('cpu_percent', 0)} | {proc.get('memory_percent', 0)} | {cmdline} |\n"

            doc += "\n"

            # Sort by memory usage
            sorted_procs = sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)

            doc += "### Top Processes by Memory\n\n"
            doc += "| Process | User | Memory % | Memory MB |\n"
            doc += "|---------|------|----------|----------|\n"

            for proc in sorted_procs[:10]:
                doc += f"| {proc.get('name', 'N/A')} | {proc.get('user', 'N/A')} | {proc.get('memory_percent', 0)} | - |\n"

            doc += "\n"

        return doc

    def _generate_network_section(self) -> str:
        """Generate network section"""
        doc = "## Network Configuration\n\n"

        # Listening ports
        listening = self.data.get('processes', {}).get('listening_ports', [])
        if listening:
            doc += "### Listening Ports\n\n"
            doc += "| Port | Process | Address |\n"
            doc += "|------|---------|--------|\n"

            for port in sorted(listening, key=lambda x: x.get('port', 0)):
                doc += f"| {port.get('port', 'N/A')} | {port.get('process', 'N/A')} | {port.get('addr', '*')} |\n"

            doc += "\n"

        # Active connections
        connections = self.data.get('processes', {}).get('connections', [])
        established = [c for c in connections if c.get('status') == 'ESTABLISHED']

        if established:
            doc += "### Active Connections\n\n"
            doc += "| Process | Local | Remote | Status |\n"
            doc += "|---------|-------|--------|--------|\n"

            for conn in established[:20]:
                local = f"{conn.get('local_addr', '*')}:{conn.get('local_port', '')}"
                remote = f"{conn.get('remote_addr', '*')}:{conn.get('remote_port', '')}"
                doc += f"| {conn.get('process', 'N/A')} | {local} | {remote} | {conn.get('status', '')} |\n"

            doc += "\n"

        # Data flows from summary
        flows = self.data.get('summary', {}).get('data_flows', [])
        if flows:
            doc += "### Data Flow Summary\n\n"
            doc += "The following data flows have been identified:\n\n"
            for flow in flows[:15]:
                doc += f"- **{flow.get('process', 'Unknown')}**: {flow.get('local', '')} -> {flow.get('remote', '')}\n"
            doc += "\n"

        return doc

    def _generate_storage_section(self) -> str:
        """Generate storage section"""
        doc = "## Storage\n\n"

        disk_usage = self.data.get('processes', {}).get('resource_usage', {}).get('disk', {})

        if disk_usage:
            doc += "### Disk Usage\n\n"
            doc += "| Mount Point | Total | Used | Free | Usage % |\n"
            doc += "|-------------|-------|------|------|--------|\n"

            for mount, usage in disk_usage.items():
                total_gb = round(usage.get('total', 0) / 1024 / 1024 / 1024, 2)
                used_gb = round(usage.get('used', 0) / 1024 / 1024 / 1024, 2)
                free_gb = round(usage.get('free', 0) / 1024 / 1024 / 1024, 2)
                percent = usage.get('percent', 0)
                doc += f"| {mount} | {total_gb} GB | {used_gb} GB | {free_gb} GB | {percent}% |\n"

            doc += "\n"

        # Important paths
        important = self.data.get('files', {}).get('important_paths', [])
        if important:
            doc += "### Important Directories\n\n"
            doc += "| Path | Size | Contents |\n"
            doc += "|------|------|----------|\n"

            for path in important:
                doc += f"| {path.get('path', '')} | {path.get('size', 'N/A')} | {path.get('contents_count', 0)} items |\n"

            doc += "\n"

        return doc

    def _generate_configuration_section(self) -> str:
        """Generate configuration section"""
        doc = "## Configuration Files\n\n"

        # Service configs
        service_configs = self.data.get('files', {}).get('service_configs', {})

        if service_configs:
            doc += "### Service Configuration Locations\n\n"

            for service, configs in service_configs.items():
                if configs:
                    doc += f"#### {service.title()}\n\n"
                    for config in configs:
                        doc += f"- `{config.get('path', 'N/A')}`\n"
                        if config.get('files'):
                            for f in config['files'][:5]:
                                doc += f"  - {f.get('name', '')}\n"
                    doc += "\n"

        # Recently modified configs
        recent = self.data.get('files', {}).get('recently_modified', [])
        if recent:
            doc += "### Recently Modified Files\n\n"
            doc += "| File | Size |\n"
            doc += "|------|------|\n"

            for f in recent[:15]:
                doc += f"| {f.get('path', 'N/A')} | {f.get('size', 0)} bytes |\n"

            doc += "\n"

        return doc

    def _generate_dependencies_section(self) -> str:
        """Generate dependencies section"""
        doc = "## Dependencies & Packages\n\n"

        # Installed packages
        packages = self.data.get('files', {}).get('installed_packages', [])

        if packages:
            # Group by package manager
            by_manager = {}
            for pkg in packages:
                manager = pkg.get('manager', 'unknown')
                if manager not in by_manager:
                    by_manager[manager] = []
                by_manager[manager].append(pkg)

            for manager, pkgs in by_manager.items():
                doc += f"### {manager.upper()} Packages ({len(pkgs)})\n\n"
                doc += "<details>\n<summary>Click to expand</summary>\n\n"
                doc += "| Package | Version |\n"
                doc += "|---------|--------|\n"

                for pkg in sorted(pkgs, key=lambda x: x.get('name', ''))[:50]:
                    doc += f"| {pkg.get('name', 'N/A')} | {pkg.get('version', 'N/A')} |\n"

                if len(pkgs) > 50:
                    doc += f"\n*... and {len(pkgs) - 50} more packages*\n"

                doc += "\n</details>\n\n"

        # Setup commands from history
        setup_cmds = self.data.get('history', {}).get('setup_commands', [])
        if setup_cmds:
            doc += "### Installation Commands (from history)\n\n"
            doc += "The following installation/setup commands were found in bash history:\n\n"
            doc += "```bash\n"
            for cmd in setup_cmds[:30]:
                doc += f"{cmd.get('command', '')}\n"
            doc += "```\n\n"

        return doc

    def _generate_troubleshooting_section(self) -> str:
        """Generate troubleshooting section"""
        doc = "## Troubleshooting Guide\n\n"

        # Identified issues
        issues = self.data.get('summary', {}).get('potential_issues', [])
        if issues:
            doc += "### Current Issues\n\n"
            for issue in issues:
                doc += f"- {issue}\n"
            doc += "\n"

        # Generic troubleshooting by detected services
        purpose = self.data.get('summary', {}).get('server_purpose', '')

        doc += "### Common Troubleshooting Steps\n\n"

        if 'web_server' in purpose:
            doc += """#### Web Server Issues
- Check web server status: `systemctl status nginx` or `systemctl status apache2`
- View access logs: `tail -f /var/log/nginx/access.log`
- View error logs: `tail -f /var/log/nginx/error.log`
- Test configuration: `nginx -t` or `apache2ctl configtest`
- Restart service: `systemctl restart nginx`

"""

        if 'database' in purpose:
            doc += """#### Database Issues
- Check database status: `systemctl status mysql` or `systemctl status postgresql`
- View database logs: Check `/var/log/mysql/` or `/var/log/postgresql/`
- Check connections: `netstat -tlnp | grep :3306` (MySQL) or `grep :5432` (PostgreSQL)
- Test connectivity: `mysql -u root -p` or `psql -U postgres`

"""

        if 'container' in purpose or 'docker' in purpose:
            doc += """#### Container Issues
- List containers: `docker ps -a`
- View container logs: `docker logs <container_id>`
- Check Docker status: `systemctl status docker`
- Inspect container: `docker inspect <container_id>`
- Check resource usage: `docker stats`

"""

        if 'kubernetes' in purpose:
            doc += """#### Kubernetes Issues
- Check node status: `kubectl get nodes`
- Check pods: `kubectl get pods --all-namespaces`
- View pod logs: `kubectl logs <pod_name>`
- Describe pod: `kubectl describe pod <pod_name>`
- Check events: `kubectl get events --sort-by='.lastTimestamp'`

"""

        # General troubleshooting
        doc += """#### General System Issues
- Check system logs: `journalctl -xe`
- Check disk space: `df -h`
- Check memory: `free -h`
- Check running processes: `ps aux | head -20`
- Check network connections: `ss -tuln`
- Check system load: `uptime`
- View recent logins: `last`

"""

        return doc

    def _generate_footer(self) -> str:
        """Generate document footer"""
        return f"""---

## Appendix

### Analysis Metadata
- **Hostname:** {self.hostname}
- **Analysis Timestamp:** {self.data.get('timestamp', 'Unknown')}
- **Processes Analyzed:** {len(self.data.get('processes', {}).get('running', []))}
- **Services Found:** {len(self.data.get('processes', {}).get('services', []))}
- **Configuration Files:** {len(self.data.get('files', {}).get('configurations', []))}

### GitLab Projects
"""
        gitlab = self.data.get('gitlab', {})
        projects = gitlab.get('projects', [])
        if projects:
            return f"""- Found {len(projects)} related projects
""" + "\n".join([f"  - {p.get('path', 'N/A')}" for p in projects[:10]])
        else:
            return "- No GitLab integration configured\n"

        doc += """
### Harbor Registry
"""
        harbor = self.data.get('harbor', {})
        repos = harbor.get('repositories', [])
        if repos:
            doc += f"- Found {len(repos)} repositories\n"
        else:
            doc += "- No Harbor integration configured\n"

        doc += "\n---\n*Document generated by System Analyzer*\n"
        return doc
