"""
Pattern Learning Module for Multi-Source Analysis

This module extracts patterns from SSH/WinRM analysis data and saves them to
the unified pattern learning database. It uses the same heuristics as the
Datadog analyzer to ensure consistent pattern detection across data sources.
"""

import hashlib
import json
import statistics
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Try to import database functions
try:
    from web.database import (
        save_pattern, save_insight, save_analysis_history,
        save_baseline, get_patterns, is_novel_pattern,
        get_baselines_for_comparison
    )
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False


@dataclass
class LearnedPattern:
    """Represents a pattern learned from analysis data."""
    pattern_type: str
    description: str
    metrics_involved: List[str]
    server_type: Optional[str] = None
    confidence: float = 1.0
    is_novel: bool = False
    metadata: Dict[str, Any] = None
    is_actionable: bool = False
    suggested_action: Optional[str] = None


@dataclass
class AnalysisInsight:
    """An insight derived from analysis."""
    category: str  # 'performance', 'capacity', 'security', 'configuration', 'recommendation'
    severity: str  # 'info', 'warning', 'critical'
    title: str
    description: str
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    suggested_action: Optional[str] = None


# Server type detection patterns (shared with Datadog analyzer)
SERVER_TYPE_PATTERNS = {
    'web_server': ['nginx', 'apache', 'httpd', 'caddy', 'lighttpd', 'iis', 'w3wp'],
    'app_server': ['gunicorn', 'uwsgi', 'unicorn', 'puma', 'node', 'java', 'dotnet', 'tomcat'],
    'database': ['mysql', 'postgres', 'mongodb', 'redis', 'memcached', 'mariadb', 'mssql', 'oracle'],
    'container_host': ['docker', 'containerd', 'podman', 'crio'],
    'kubernetes': ['kubelet', 'kube-proxy', 'etcd', 'kube-apiserver'],
    'message_queue': ['rabbitmq', 'kafka', 'activemq', 'nats', 'zeromq'],
    'cache': ['redis', 'memcached', 'varnish', 'haproxy', 'squid'],
    'monitoring': ['prometheus', 'grafana', 'zabbix', 'nagios', 'datadog-agent'],
    'ci_cd': ['jenkins', 'gitlab-runner', 'drone', 'teamcity', 'bamboo'],
    'mail': ['postfix', 'dovecot', 'sendmail', 'exim', 'exchange'],
    'dns': ['named', 'bind', 'dnsmasq', 'unbound', 'coredns'],
    'file_server': ['smbd', 'nfsd', 'vsftpd', 'proftpd'],
    'vpn': ['openvpn', 'wireguard', 'strongswan', 'ipsec'],
    'proxy': ['nginx', 'haproxy', 'envoy', 'traefik', 'squid'],
    'logging': ['elasticsearch', 'logstash', 'fluentd', 'rsyslog', 'filebeat'],
}

# Resource usage thresholds
THRESHOLDS = {
    'cpu_high': 80,
    'cpu_critical': 95,
    'memory_high': 80,
    'memory_critical': 95,
    'disk_high': 80,
    'disk_critical': 90,
    'load_per_cpu_high': 1.5,
    'load_per_cpu_critical': 3.0,
}


class PatternLearner:
    """
    Extracts and learns patterns from SSH/WinRM analysis data.

    This class analyzes the results of remote system analysis and:
    1. Detects server types from running processes and services
    2. Identifies resource usage patterns
    3. Extracts configuration patterns
    4. Generates insights and recommendations
    5. Saves all patterns to the unified learning database
    """

    def __init__(self, source: str = 'ssh'):
        """
        Initialize the pattern learner.

        Args:
            source: The data source ('ssh' or 'winrm')
        """
        self.source = source
        self.patterns: List[LearnedPattern] = []
        self.insights: List[AnalysisInsight] = []

    def learn_from_analysis(self, hostname: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point: learn patterns from analysis data and save to database.

        Args:
            hostname: The hostname of the analyzed server
            analysis_data: The complete analysis data from SSH/WinRM analysis

        Returns:
            Summary of learned patterns and insights
        """
        self.patterns = []
        self.insights = []

        # Extract patterns from different analysis sections
        server_types = self._detect_server_types(analysis_data)
        self._analyze_processes(analysis_data.get('processes', {}))
        self._analyze_resource_usage(analysis_data.get('processes', {}).get('resource_usage', {}))
        self._analyze_services(analysis_data.get('processes', {}).get('services', []))
        self._analyze_packages(analysis_data.get('files', {}).get('installed_packages', []))
        self._analyze_history(analysis_data.get('history', {}))
        self._analyze_network(analysis_data.get('processes', {}).get('connections', []))
        self._analyze_secrets(analysis_data.get('secrets', {}))

        # Save to database if available
        pattern_count = 0
        novel_count = 0
        if DB_AVAILABLE:
            pattern_count, novel_count = self._save_patterns(hostname, server_types)
            self._save_insights(hostname)
            self._save_history(hostname, server_types, analysis_data)
            self._save_baselines(hostname, analysis_data)

        return {
            'hostname': hostname,
            'source': self.source,
            'server_types': server_types,
            'patterns_detected': len(self.patterns),
            'patterns_saved': pattern_count,
            'novel_patterns': novel_count,
            'insights': [asdict(i) for i in self.insights],
            'health_indicators': self._calculate_health_indicators()
        }

    def _detect_server_types(self, analysis_data: Dict[str, Any]) -> List[str]:
        """Detect server types from processes and services."""
        detected_types = set()

        # Check running processes
        processes = analysis_data.get('processes', {}).get('running', [])
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            cmdline = proc.get('cmdline', '').lower()

            for server_type, indicators in SERVER_TYPE_PATTERNS.items():
                for indicator in indicators:
                    if indicator in proc_name or indicator in cmdline:
                        detected_types.add(server_type)
                        break

        # Check services
        services = analysis_data.get('processes', {}).get('services', [])
        for service in services:
            service_name = service.get('name', '').lower()
            if service.get('active') == 'active':
                for server_type, indicators in SERVER_TYPE_PATTERNS.items():
                    for indicator in indicators:
                        if indicator in service_name:
                            detected_types.add(server_type)
                            break

        return list(detected_types)

    def _analyze_processes(self, processes_data: Dict[str, Any]):
        """Analyze running processes for patterns."""
        running = processes_data.get('running', [])
        if not running:
            return

        # Find high CPU processes
        high_cpu_procs = [p for p in running if p.get('cpu_percent', 0) > 50]
        if high_cpu_procs:
            pattern = LearnedPattern(
                pattern_type='high_cpu_process',
                description=f"Processes with high CPU usage detected",
                metrics_involved=['cpu_percent'],
                confidence=0.9,
                metadata={
                    'processes': [p.get('name') for p in high_cpu_procs[:5]],
                    'max_cpu': max(p.get('cpu_percent', 0) for p in high_cpu_procs)
                },
                is_actionable=True,
                suggested_action="Review high CPU processes for optimization opportunities"
            )
            self.patterns.append(pattern)

        # Find high memory processes
        high_mem_procs = [p for p in running if p.get('memory_percent', 0) > 20]
        if high_mem_procs:
            pattern = LearnedPattern(
                pattern_type='high_memory_process',
                description=f"Processes with high memory usage detected",
                metrics_involved=['memory_percent'],
                confidence=0.9,
                metadata={
                    'processes': [p.get('name') for p in high_mem_procs[:5]],
                    'max_memory': max(p.get('memory_percent', 0) for p in high_mem_procs)
                }
            )
            self.patterns.append(pattern)

        # Process signature pattern (what combination of processes run together)
        proc_names = sorted(set(p.get('name', '') for p in running if p.get('name')))
        if len(proc_names) > 3:
            # Create a hash of the process signature
            signature = ':'.join(proc_names[:20])  # Top 20 processes
            pattern = LearnedPattern(
                pattern_type='process_signature',
                description=f"Server process signature ({len(proc_names)} unique processes)",
                metrics_involved=['process_list'],
                confidence=0.8,
                metadata={'process_count': len(proc_names), 'top_processes': proc_names[:10]}
            )
            self.patterns.append(pattern)

    def _analyze_resource_usage(self, resource_data: Dict[str, Any]):
        """Analyze resource usage for patterns and insights."""
        if not resource_data:
            return

        # CPU analysis
        cpu_data = resource_data.get('cpu', {})
        load_avg = cpu_data.get('load_avg', [])
        cpu_count = cpu_data.get('count', 1)

        if load_avg and cpu_count:
            load_per_cpu = load_avg[0] / cpu_count if cpu_count > 0 else load_avg[0]

            if load_per_cpu > THRESHOLDS['load_per_cpu_critical']:
                self.insights.append(AnalysisInsight(
                    category='performance',
                    severity='critical',
                    title='Critical CPU load',
                    description=f'Load per CPU is {load_per_cpu:.2f}, indicating severe CPU pressure',
                    metric_name='load_per_cpu',
                    metric_value=load_per_cpu,
                    threshold=THRESHOLDS['load_per_cpu_critical'],
                    suggested_action='Scale horizontally or optimize CPU-intensive processes'
                ))
            elif load_per_cpu > THRESHOLDS['load_per_cpu_high']:
                self.insights.append(AnalysisInsight(
                    category='performance',
                    severity='warning',
                    title='High CPU load',
                    description=f'Load per CPU is {load_per_cpu:.2f}',
                    metric_name='load_per_cpu',
                    metric_value=load_per_cpu,
                    threshold=THRESHOLDS['load_per_cpu_high']
                ))

        # Memory analysis
        memory_data = resource_data.get('memory', {})
        mem_percent = memory_data.get('percent', 0)

        if mem_percent > THRESHOLDS['memory_critical']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='critical',
                title='Critical memory usage',
                description=f'Memory usage at {mem_percent:.1f}%',
                metric_name='memory_percent',
                metric_value=mem_percent,
                threshold=THRESHOLDS['memory_critical'],
                suggested_action='Add memory or identify memory leaks'
            ))
        elif mem_percent > THRESHOLDS['memory_high']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='warning',
                title='High memory usage',
                description=f'Memory usage at {mem_percent:.1f}%',
                metric_name='memory_percent',
                metric_value=mem_percent,
                threshold=THRESHOLDS['memory_high']
            ))

        # Disk analysis
        disk_data = resource_data.get('disk', {})
        for mount_point, disk_info in disk_data.items():
            disk_percent = disk_info.get('percent', 0)
            if disk_percent > THRESHOLDS['disk_critical']:
                self.insights.append(AnalysisInsight(
                    category='capacity',
                    severity='critical',
                    title=f'Critical disk usage on {mount_point}',
                    description=f'Disk usage at {disk_percent}%',
                    metric_name=f'disk_percent_{mount_point}',
                    metric_value=disk_percent,
                    threshold=THRESHOLDS['disk_critical'],
                    suggested_action='Free up disk space or expand storage'
                ))
            elif disk_percent > THRESHOLDS['disk_high']:
                self.insights.append(AnalysisInsight(
                    category='capacity',
                    severity='warning',
                    title=f'High disk usage on {mount_point}',
                    description=f'Disk usage at {disk_percent}%',
                    metric_name=f'disk_percent_{mount_point}',
                    metric_value=disk_percent,
                    threshold=THRESHOLDS['disk_high']
                ))

        # Resource pattern
        if cpu_data or memory_data or disk_data:
            pattern = LearnedPattern(
                pattern_type='resource_profile',
                description='Server resource utilization profile',
                metrics_involved=['cpu', 'memory', 'disk'],
                confidence=0.95,
                metadata={
                    'cpu_count': cpu_count,
                    'load_avg': load_avg,
                    'memory_percent': mem_percent,
                    'disk_usage': {k: v.get('percent', 0) for k, v in disk_data.items()}
                }
            )
            self.patterns.append(pattern)

    def _analyze_services(self, services: List[Dict[str, Any]]):
        """Analyze services for patterns."""
        if not services:
            return

        active_services = [s for s in services if s.get('active') == 'active']
        failed_services = [s for s in services if s.get('status') == 'failed']

        # Service profile pattern
        if active_services:
            service_names = sorted([s.get('name', '') for s in active_services])
            pattern = LearnedPattern(
                pattern_type='service_profile',
                description=f'Active service profile ({len(active_services)} services)',
                metrics_involved=['services'],
                confidence=0.9,
                metadata={
                    'active_count': len(active_services),
                    'services': service_names[:20]
                }
            )
            self.patterns.append(pattern)

        # Failed services insight
        if failed_services:
            self.insights.append(AnalysisInsight(
                category='configuration',
                severity='warning',
                title=f'{len(failed_services)} failed service(s)',
                description=f'Services in failed state: {", ".join(s.get("name", "") for s in failed_services[:5])}',
                suggested_action='Review and restart failed services or fix configuration issues'
            ))

    def _analyze_packages(self, packages: List[Dict[str, Any]]):
        """Analyze installed packages for patterns."""
        if not packages:
            return

        # Group by package manager
        managers = {}
        for pkg in packages:
            manager = pkg.get('manager', 'unknown')
            if manager not in managers:
                managers[manager] = []
            managers[manager].append(pkg)

        # Package profile pattern
        pattern = LearnedPattern(
            pattern_type='package_profile',
            description=f'Installed package profile ({len(packages)} packages)',
            metrics_involved=['packages'],
            confidence=0.85,
            metadata={
                'total_packages': len(packages),
                'by_manager': {k: len(v) for k, v in managers.items()},
                'sample_packages': [p.get('name') for p in packages[:20]]
            }
        )
        self.patterns.append(pattern)

    def _analyze_history(self, history_data: Dict[str, Any]):
        """Analyze command history for patterns."""
        if not history_data:
            return

        setup_commands = history_data.get('setup_commands', [])
        package_installs = history_data.get('package_installations', [])
        service_changes = history_data.get('service_changes', [])

        # Setup pattern
        if setup_commands or package_installs:
            pattern = LearnedPattern(
                pattern_type='setup_pattern',
                description='Server setup and configuration pattern',
                metrics_involved=['history'],
                confidence=0.75,
                metadata={
                    'setup_command_count': len(setup_commands),
                    'package_install_count': len(package_installs),
                    'service_change_count': len(service_changes),
                    'sample_commands': [c.get('command', '') for c in setup_commands[:10]]
                }
            )
            self.patterns.append(pattern)

        # Recent service changes insight
        if service_changes:
            self.insights.append(AnalysisInsight(
                category='configuration',
                severity='info',
                title=f'{len(service_changes)} recent service change(s)',
                description='Service configuration changes detected in command history',
                metric_name='service_changes',
                metric_value=len(service_changes)
            ))

    def _analyze_network(self, connections: List[Dict[str, Any]]):
        """Analyze network connections for patterns."""
        if not connections:
            return

        # Group by type and status
        listening = [c for c in connections if c.get('status') == 'LISTEN']
        established = [c for c in connections if c.get('status') == 'ESTABLISHED']

        # Listening ports pattern
        if listening:
            ports = sorted(set(c.get('local_port', 0) for c in listening))
            pattern = LearnedPattern(
                pattern_type='listening_ports',
                description=f'Network listening profile ({len(ports)} ports)',
                metrics_involved=['network'],
                confidence=0.95,
                metadata={
                    'port_count': len(ports),
                    'ports': ports[:30],
                    'processes': list(set(c.get('process', '') for c in listening if c.get('process')))
                }
            )
            self.patterns.append(pattern)

        # Connection pattern
        if established:
            pattern = LearnedPattern(
                pattern_type='network_connections',
                description=f'Active connections profile ({len(established)} established)',
                metrics_involved=['network'],
                confidence=0.8,
                metadata={
                    'established_count': len(established),
                    'remote_hosts': list(set(c.get('remote_addr', '') for c in established))[:20]
                }
            )
            self.patterns.append(pattern)

    def _analyze_secrets(self, secrets_data: Dict[str, Any]):
        """Analyze secrets and keys for security patterns."""
        if not secrets_data:
            return

        ssh_keys = secrets_data.get('ssh_keys', [])
        authorized_keys = secrets_data.get('authorized_keys', [])

        # SSH key security pattern
        unencrypted_keys = [k for k in ssh_keys if not k.get('encrypted', True) and not k.get('is_host_key', False)]
        if unencrypted_keys:
            self.insights.append(AnalysisInsight(
                category='security',
                severity='warning',
                title='Unencrypted SSH private keys found',
                description=f'{len(unencrypted_keys)} SSH private key(s) without passphrase protection',
                suggested_action='Protect private keys with passphrases for enhanced security'
            ))

        # Authorized keys pattern
        if authorized_keys:
            total_keys = sum(k.get('key_count', 0) for k in authorized_keys)
            pattern = LearnedPattern(
                pattern_type='ssh_access_profile',
                description=f'SSH access profile ({total_keys} authorized keys)',
                metrics_involved=['ssh_keys'],
                confidence=0.9,
                metadata={
                    'authorized_key_count': total_keys,
                    'users_with_keys': [k.get('owner', '') for k in authorized_keys]
                }
            )
            self.patterns.append(pattern)

    def _calculate_pattern_hash(self, pattern: LearnedPattern) -> str:
        """Calculate a unique hash for a pattern."""
        # Include type, description prefix, and key metadata
        hash_data = {
            'type': pattern.pattern_type,
            'desc_prefix': pattern.description[:50],
            'metrics': sorted(pattern.metrics_involved),
            'server_type': pattern.server_type
        }
        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()[:16]

    def _calculate_insight_hash(self, insight: AnalysisInsight) -> str:
        """Calculate a unique hash for an insight."""
        hash_data = {
            'category': insight.category,
            'title': insight.title,
            'metric': insight.metric_name
        }
        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()[:16]

    def _save_patterns(self, hostname: str, server_types: List[str]) -> Tuple[int, int]:
        """Save patterns to the database."""
        saved_count = 0
        novel_count = 0

        for pattern in self.patterns:
            pattern_hash = self._calculate_pattern_hash(pattern)
            is_novel = is_novel_pattern(pattern_hash)

            if is_novel:
                novel_count += 1

            # Set server type if detected
            if server_types and not pattern.server_type:
                pattern.server_type = server_types[0] if len(server_types) == 1 else ','.join(server_types[:3])

            save_pattern(
                pattern_hash=pattern_hash,
                pattern_type=pattern.pattern_type,
                description=pattern.description,
                metrics_involved=pattern.metrics_involved,
                server_type=pattern.server_type,
                confidence=pattern.confidence,
                metadata=pattern.metadata,
                is_actionable=pattern.is_actionable,
                suggested_action=pattern.suggested_action,
                source=self.source
            )
            saved_count += 1

        return saved_count, novel_count

    def _save_insights(self, hostname: str):
        """Save insights to the database."""
        for insight in self.insights:
            insight_hash = self._calculate_insight_hash(insight)
            save_insight(
                hostname=hostname,
                insight_hash=insight_hash,
                category=insight.category,
                severity=insight.severity,
                title=insight.title,
                description=insight.description,
                metric_name=insight.metric_name,
                metric_value=insight.metric_value,
                threshold=insight.threshold,
                suggested_action=insight.suggested_action,
                source=self.source
            )

    def _save_history(self, hostname: str, server_types: List[str], analysis_data: Dict[str, Any]):
        """Save analysis history to the database."""
        critical_count = sum(1 for i in self.insights if i.severity == 'critical')
        warning_count = sum(1 for i in self.insights if i.severity == 'warning')

        # Calculate a simple health score
        health_score = 100
        health_score -= critical_count * 20
        health_score -= warning_count * 5
        health_score = max(0, min(100, health_score))

        save_analysis_history(
            hostname=hostname,
            health_score=health_score,
            server_types=server_types,
            critical_count=critical_count,
            warning_count=warning_count,
            pattern_count=len(self.patterns),
            analysis_data={
                'patterns': [asdict(p) for p in self.patterns],
                'source': self.source,
                'analyzed_at': datetime.now().isoformat()
            },
            source=self.source
        )

    def _save_baselines(self, hostname: str, analysis_data: Dict[str, Any]):
        """Save resource baselines to the database."""
        resource_data = analysis_data.get('processes', {}).get('resource_usage', {})
        if not resource_data:
            return

        now = datetime.now()

        # CPU baseline
        cpu_data = resource_data.get('cpu', {})
        load_avg = cpu_data.get('load_avg', [])
        if load_avg:
            save_baseline(
                hostname=hostname,
                metric_name='load_avg_1m',
                baseline_avg=load_avg[0],
                baseline_min=load_avg[0] * 0.5,
                baseline_max=load_avg[0] * 1.5,
                baseline_stddev=load_avg[0] * 0.2,
                sample_count=1,
                period_start=now,
                period_end=now,
                source=self.source
            )

        # Memory baseline
        memory_data = resource_data.get('memory', {})
        if memory_data.get('percent'):
            save_baseline(
                hostname=hostname,
                metric_name='memory_percent',
                baseline_avg=memory_data['percent'],
                baseline_min=memory_data['percent'] * 0.5,
                baseline_max=min(100, memory_data['percent'] * 1.5),
                baseline_stddev=memory_data['percent'] * 0.1,
                sample_count=1,
                period_start=now,
                period_end=now,
                source=self.source
            )

        # Disk baselines
        disk_data = resource_data.get('disk', {})
        for mount_point, disk_info in disk_data.items():
            if disk_info.get('percent'):
                metric_name = f"disk_percent_{mount_point.replace('/', '_')}"
                save_baseline(
                    hostname=hostname,
                    metric_name=metric_name,
                    baseline_avg=disk_info['percent'],
                    baseline_min=disk_info['percent'] * 0.8,
                    baseline_max=min(100, disk_info['percent'] * 1.2),
                    baseline_stddev=disk_info['percent'] * 0.05,
                    sample_count=1,
                    period_start=now,
                    period_end=now,
                    source=self.source
                )

    def _calculate_health_indicators(self) -> Dict[str, Any]:
        """Calculate overall health indicators from insights."""
        critical_count = sum(1 for i in self.insights if i.severity == 'critical')
        warning_count = sum(1 for i in self.insights if i.severity == 'warning')
        info_count = sum(1 for i in self.insights if i.severity == 'info')

        # Calculate health score
        health_score = 100
        health_score -= critical_count * 20
        health_score -= warning_count * 5
        health_score = max(0, min(100, health_score))

        # Determine health status
        if critical_count > 0:
            status = 'critical'
        elif warning_count > 2:
            status = 'warning'
        elif warning_count > 0:
            status = 'fair'
        else:
            status = 'healthy'

        return {
            'health_score': health_score,
            'status': status,
            'critical_issues': critical_count,
            'warnings': warning_count,
            'info_items': info_count,
            'total_patterns': len(self.patterns)
        }


def learn_patterns_from_analysis(hostname: str, analysis_data: Dict[str, Any],
                                  source: str = 'ssh') -> Dict[str, Any]:
    """
    Convenience function to learn patterns from analysis data.

    Args:
        hostname: The hostname of the analyzed server
        analysis_data: The complete analysis data dictionary
        source: The data source ('ssh' or 'winrm')

    Returns:
        Summary of learned patterns and insights
    """
    learner = PatternLearner(source=source)
    return learner.learn_from_analysis(hostname, analysis_data)


def compare_sources(hostname: str) -> Dict[str, Any]:
    """
    Compare patterns and baselines from different sources for a host.

    This is useful for validating that Datadog metrics match what's observed
    via SSH/WinRM direct analysis.

    Args:
        hostname: The hostname to compare

    Returns:
        Comparison data showing differences between sources
    """
    if not DB_AVAILABLE:
        return {'error': 'Database not available'}

    # Get patterns from different sources
    datadog_patterns = get_patterns(source='datadog')
    ssh_patterns = get_patterns(source='ssh')
    winrm_patterns = get_patterns(source='winrm')

    # Get baselines for comparison
    baselines = get_baselines_for_comparison(hostname)

    # Build comparison
    comparison = {
        'hostname': hostname,
        'pattern_counts': {
            'datadog': len([p for p in datadog_patterns if p.get('server_type')]),
            'ssh': len([p for p in ssh_patterns if p.get('server_type')]),
            'winrm': len([p for p in winrm_patterns if p.get('server_type')])
        },
        'baseline_comparison': {}
    }

    # Compare baselines across sources
    for metric_name, sources in baselines.items():
        if len(sources) > 1:
            comparison['baseline_comparison'][metric_name] = {
                source: {
                    'avg': data.get('baseline_avg'),
                    'min': data.get('baseline_min'),
                    'max': data.get('baseline_max')
                }
                for source, data in sources.items()
            }

    return comparison
