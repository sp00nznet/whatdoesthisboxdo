"""
Datadog Analyzer
Applies heuristics to Datadog metrics data to infer server purpose,
identify issues, and suggest improvements.
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AnalysisInsight:
    """Represents a single insight from analysis"""
    category: str  # 'performance', 'capacity', 'anomaly', 'recommendation'
    severity: str  # 'info', 'warning', 'critical'
    title: str
    description: str
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    suggested_action: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class PatternMatch:
    """Represents a detected pattern in metrics"""
    pattern_type: str  # 'spike', 'trend', 'periodic', 'anomaly', 'correlation'
    description: str
    metrics_involved: List[str]
    time_range: Optional[Tuple[datetime, datetime]] = None
    confidence: float = 1.0
    is_novel: bool = False  # True if this pattern hasn't been seen before
    metadata: Dict[str, Any] = field(default_factory=dict)


class DatadogAnalyzer:
    """
    Analyzes Datadog data using heuristics to understand server behavior,
    identify patterns, and provide actionable insights.
    """

    # Thresholds for various metrics (can be customized)
    DEFAULT_THRESHOLDS = {
        'cpu_critical': 90,
        'cpu_warning': 70,
        'cpu_idle_waste': 10,  # Below this, server may be overprovisioned
        'memory_critical': 90,
        'memory_warning': 80,
        'memory_idle_waste': 30,
        'disk_critical': 90,
        'disk_warning': 80,
        'load_per_cpu_warning': 1.5,  # Load per CPU core
        'load_per_cpu_critical': 3.0,
        'network_spike_multiplier': 3.0,  # X times average is a spike
        'variance_threshold': 0.3,  # Coefficient of variation threshold for variability
    }

    # Process name patterns for server type inference
    SERVER_TYPE_PATTERNS = {
        'web_server': ['nginx', 'apache', 'httpd', 'caddy', 'lighttpd', 'traefik'],
        'app_server': ['gunicorn', 'uwsgi', 'unicorn', 'puma', 'passenger', 'pm2', 'node', 'java', 'dotnet'],
        'database': ['mysql', 'postgres', 'mongodb', 'redis', 'memcached', 'elastic', 'cassandra', 'mariadb'],
        'container_host': ['docker', 'containerd', 'podman', 'crio'],
        'kubernetes': ['kubelet', 'kube-proxy', 'etcd', 'kube-apiserver', 'kube-controller', 'kube-scheduler'],
        'message_queue': ['rabbitmq', 'kafka', 'activemq', 'celery', 'sidekiq', 'resque'],
        'cache': ['redis', 'memcached', 'varnish', 'haproxy'],
        'monitoring': ['prometheus', 'grafana', 'datadog', 'nagios', 'zabbix', 'telegraf', 'collectd'],
        'ci_cd': ['jenkins', 'gitlab-runner', 'drone', 'buildkite', 'circleci'],
        'mail': ['postfix', 'dovecot', 'sendmail', 'exim'],
    }

    def __init__(self, thresholds: Dict[str, float] = None):
        """
        Initialize analyzer with optional custom thresholds.

        Args:
            thresholds: Custom threshold values to override defaults
        """
        self.thresholds = {**self.DEFAULT_THRESHOLDS}
        if thresholds:
            self.thresholds.update(thresholds)

        self.insights: List[AnalysisInsight] = []
        self.patterns: List[PatternMatch] = []
        self.server_types: List[str] = []

    def analyze(self, datadog_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on Datadog data.

        Args:
            datadog_data: Data from DatadogConnector.get_all_data_for_host()

        Returns:
            Analysis results dictionary
        """
        self.insights = []
        self.patterns = []
        self.server_types = []

        hostname = datadog_data.get('hostname', 'unknown')
        metrics = datadog_data.get('metrics', {})
        processes = datadog_data.get('processes', [])
        monitors = datadog_data.get('monitors', [])
        events = datadog_data.get('events', [])
        tags = datadog_data.get('tags', [])

        logger.info(f"Analyzing Datadog data for {hostname}")

        # Run all analysis methods
        self._analyze_cpu_metrics(metrics)
        self._analyze_memory_metrics(metrics)
        self._analyze_disk_metrics(metrics)
        self._analyze_network_metrics(metrics)
        self._analyze_load_metrics(metrics)
        self._analyze_processes(processes)
        self._analyze_monitors(monitors)
        self._analyze_events(events)
        self._analyze_tags(tags)
        self._detect_patterns(metrics)
        self._infer_server_purpose(processes, tags, metrics)
        self._generate_recommendations()

        # Calculate overall health score
        health_score = self._calculate_health_score()

        return {
            'hostname': hostname,
            'timestamp': datetime.now().isoformat(),
            'health_score': health_score,
            'server_types': self.server_types,
            'insights': [self._insight_to_dict(i) for i in self.insights],
            'patterns': [self._pattern_to_dict(p) for p in self.patterns],
            'summary': self._generate_summary(metrics),
            'recommendations': self._get_recommendations(),
            'metric_analysis': self._get_metric_analysis(metrics)
        }

    def _analyze_cpu_metrics(self, metrics: Dict) -> None:
        """Analyze CPU-related metrics"""
        if 'cpu' not in metrics and 'cpu_user' not in metrics:
            return

        # Get CPU values
        cpu_data = metrics.get('cpu', metrics.get('cpu_user', {}))
        if not cpu_data:
            return

        cpu_avg = cpu_data.get('avg', 0)
        cpu_max = cpu_data.get('max', 0)
        cpu_min = cpu_data.get('min', 0)

        # Check for high CPU
        if cpu_avg >= self.thresholds['cpu_critical']:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='critical',
                title='Critical CPU Usage',
                description=f'Average CPU usage is {cpu_avg:.1f}%, indicating severe resource constraint',
                metric_name='cpu',
                metric_value=cpu_avg,
                threshold=self.thresholds['cpu_critical'],
                suggested_action='Scale up CPU resources or optimize CPU-intensive processes'
            ))
        elif cpu_avg >= self.thresholds['cpu_warning']:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='warning',
                title='High CPU Usage',
                description=f'Average CPU usage is {cpu_avg:.1f}%, approaching capacity limits',
                metric_name='cpu',
                metric_value=cpu_avg,
                threshold=self.thresholds['cpu_warning'],
                suggested_action='Monitor closely and plan for scaling'
            ))
        elif cpu_avg <= self.thresholds['cpu_idle_waste']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='info',
                title='Underutilized CPU',
                description=f'Average CPU usage is only {cpu_avg:.1f}%, server may be overprovisioned',
                metric_name='cpu',
                metric_value=cpu_avg,
                threshold=self.thresholds['cpu_idle_waste'],
                suggested_action='Consider downsizing to reduce costs'
            ))

        # Check for CPU spikes
        if cpu_max - cpu_avg > 40:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='warning',
                title='CPU Spikes Detected',
                description=f'CPU spiked to {cpu_max:.1f}% while average is {cpu_avg:.1f}%',
                metric_name='cpu',
                metric_value=cpu_max,
                suggested_action='Investigate processes causing CPU spikes'
            ))

        # Check CPU variability
        values = cpu_data.get('values', [])
        if values:
            variance = self._calculate_variance(values)
            if variance > self.thresholds['variance_threshold']:
                self.patterns.append(PatternMatch(
                    pattern_type='variability',
                    description='High CPU variability indicates inconsistent workload',
                    metrics_involved=['cpu'],
                    confidence=0.8,
                    metadata={'variance': variance}
                ))

    def _analyze_memory_metrics(self, metrics: Dict) -> None:
        """Analyze memory-related metrics"""
        mem_pct_data = metrics.get('memory_pct', {})
        mem_used_data = metrics.get('memory_used', {})
        mem_total_data = metrics.get('memory_total', {})

        if not mem_pct_data and not mem_used_data:
            return

        # Calculate memory percentage if we have used and total
        if mem_used_data and mem_total_data:
            mem_avg = (mem_used_data.get('avg', 0) / mem_total_data.get('avg', 1)) * 100
            mem_max = (mem_used_data.get('max', 0) / mem_total_data.get('avg', 1)) * 100
        elif mem_pct_data:
            # memory_pct is actually "usable" percentage, so invert it
            mem_avg = 100 - (mem_pct_data.get('avg', 1) * 100)
            mem_max = 100 - (mem_pct_data.get('min', 1) * 100)
        else:
            return

        # Check thresholds
        if mem_avg >= self.thresholds['memory_critical']:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='critical',
                title='Critical Memory Usage',
                description=f'Memory usage is at {mem_avg:.1f}%, risk of OOM conditions',
                metric_name='memory',
                metric_value=mem_avg,
                threshold=self.thresholds['memory_critical'],
                suggested_action='Add more RAM or identify memory leaks'
            ))
        elif mem_avg >= self.thresholds['memory_warning']:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='warning',
                title='High Memory Usage',
                description=f'Memory usage is at {mem_avg:.1f}%',
                metric_name='memory',
                metric_value=mem_avg,
                threshold=self.thresholds['memory_warning']
            ))
        elif mem_avg <= self.thresholds['memory_idle_waste']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='info',
                title='Underutilized Memory',
                description=f'Only {mem_avg:.1f}% memory in use, server may be overprovisioned',
                metric_name='memory',
                metric_value=mem_avg,
                suggested_action='Consider downsizing to reduce costs'
            ))

    def _analyze_disk_metrics(self, metrics: Dict) -> None:
        """Analyze disk-related metrics"""
        disk_use = metrics.get('disk_in_use', {})

        if not disk_use:
            return

        disk_avg = disk_use.get('avg', 0) * 100  # Convert to percentage
        disk_max = disk_use.get('max', 0) * 100

        if disk_avg >= self.thresholds['disk_critical']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='critical',
                title='Critical Disk Usage',
                description=f'Disk usage is at {disk_avg:.1f}%, immediate action required',
                metric_name='disk',
                metric_value=disk_avg,
                threshold=self.thresholds['disk_critical'],
                suggested_action='Add disk space or clean up files immediately'
            ))
        elif disk_avg >= self.thresholds['disk_warning']:
            self.insights.append(AnalysisInsight(
                category='capacity',
                severity='warning',
                title='High Disk Usage',
                description=f'Disk usage is at {disk_avg:.1f}%',
                metric_name='disk',
                metric_value=disk_avg,
                threshold=self.thresholds['disk_warning'],
                suggested_action='Plan for disk expansion or cleanup'
            ))

        # Check disk I/O
        disk_read = metrics.get('disk_read', {})
        disk_write = metrics.get('disk_write', {})

        if disk_read and disk_write:
            read_avg = disk_read.get('avg', 0)
            write_avg = disk_write.get('avg', 0)

            if read_avg > 1000 or write_avg > 1000:  # High IOPS
                self.insights.append(AnalysisInsight(
                    category='performance',
                    severity='info',
                    title='High Disk I/O',
                    description=f'Disk I/O is elevated (read: {read_avg:.0f}/s, write: {write_avg:.0f}/s)',
                    metric_name='disk_io',
                    suggested_action='Consider SSD or NVMe storage for better performance'
                ))

    def _analyze_network_metrics(self, metrics: Dict) -> None:
        """Analyze network-related metrics"""
        net_in = metrics.get('network_bytes_in', {})
        net_out = metrics.get('network_bytes_out', {})

        if not net_in and not net_out:
            return

        # Check for network-intensive workload
        in_avg = net_in.get('avg', 0) if net_in else 0
        out_avg = net_out.get('avg', 0) if net_out else 0

        # Convert to MB/s for readability
        in_mb = in_avg / 1_000_000
        out_mb = out_avg / 1_000_000

        if in_mb > 100 or out_mb > 100:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='info',
                title='High Network Throughput',
                description=f'High network activity: {in_mb:.1f} MB/s in, {out_mb:.1f} MB/s out',
                metric_name='network',
                suggested_action='This is a network-intensive workload'
            ))
            self.server_types.append('network_intensive')

        # Check for asymmetric traffic
        if in_avg > 0 and out_avg > 0:
            ratio = max(in_avg, out_avg) / min(in_avg, out_avg)
            if ratio > 10:
                direction = 'inbound' if in_avg > out_avg else 'outbound'
                self.patterns.append(PatternMatch(
                    pattern_type='asymmetric_traffic',
                    description=f'Highly asymmetric network traffic, predominantly {direction}',
                    metrics_involved=['network_bytes_in', 'network_bytes_out'],
                    confidence=0.9,
                    metadata={'ratio': ratio, 'direction': direction}
                ))

    def _analyze_load_metrics(self, metrics: Dict) -> None:
        """Analyze system load metrics"""
        load_1 = metrics.get('load_1', {})
        load_5 = metrics.get('load_5', {})
        load_15 = metrics.get('load_15', {})

        if not load_1:
            return

        load_avg = load_1.get('avg', 0)
        load_max = load_1.get('max', 0)

        # We don't know CPU count from Datadog easily, so use absolute thresholds
        if load_avg > 8:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='critical',
                title='Very High System Load',
                description=f'System load average is {load_avg:.2f}',
                metric_name='load',
                metric_value=load_avg,
                suggested_action='Investigate blocked processes and I/O wait'
            ))
        elif load_avg > 4:
            self.insights.append(AnalysisInsight(
                category='performance',
                severity='warning',
                title='High System Load',
                description=f'System load average is {load_avg:.2f}',
                metric_name='load',
                metric_value=load_avg
            ))

        # Check load trend
        if load_1 and load_15:
            load_1_avg = load_1.get('avg', 0)
            load_15_avg = load_15.get('avg', 0)

            if load_15_avg > 0 and load_1_avg / load_15_avg > 1.5:
                self.patterns.append(PatternMatch(
                    pattern_type='trend',
                    description='System load is increasing recently',
                    metrics_involved=['load_1', 'load_15'],
                    confidence=0.7,
                    metadata={'trend': 'increasing'}
                ))

    def _analyze_processes(self, processes: List[Dict]) -> None:
        """Analyze process information"""
        if not processes:
            return

        # Sort by CPU usage
        top_cpu = sorted(processes, key=lambda p: p.get('cpu_percent', 0), reverse=True)[:5]
        top_mem = sorted(processes, key=lambda p: p.get('memory_percent', 0), reverse=True)[:5]

        # Check for runaway processes
        for proc in processes:
            cpu = proc.get('cpu_percent', 0)
            if cpu > 90:
                self.insights.append(AnalysisInsight(
                    category='performance',
                    severity='warning',
                    title='High CPU Process',
                    description=f"Process '{proc.get('name')}' using {cpu:.1f}% CPU",
                    metric_name='process_cpu',
                    metric_value=cpu
                ))

        # Identify server type from processes
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            cmdline = proc.get('cmdline', '').lower()

            for server_type, patterns in self.SERVER_TYPE_PATTERNS.items():
                if any(pattern in proc_name or pattern in cmdline for pattern in patterns):
                    if server_type not in self.server_types:
                        self.server_types.append(server_type)

    def _analyze_monitors(self, monitors: List[Dict]) -> None:
        """Analyze Datadog monitors/alerts"""
        if not monitors:
            return

        alert_count = 0
        warn_count = 0

        for monitor in monitors:
            state = monitor.get('overall_state', '')
            if state == 'Alert':
                alert_count += 1
                self.insights.append(AnalysisInsight(
                    category='anomaly',
                    severity='critical',
                    title=f"Alert: {monitor.get('name', 'Unknown')}",
                    description=f"Monitor in alert state: {monitor.get('query', '')}",
                    suggested_action='Investigate and resolve the alert condition'
                ))
            elif state == 'Warn':
                warn_count += 1

        if alert_count > 0:
            self.insights.append(AnalysisInsight(
                category='anomaly',
                severity='critical',
                title='Active Alerts',
                description=f'{alert_count} monitors are in alert state',
                metric_value=alert_count
            ))

    def _analyze_events(self, events: List[Dict]) -> None:
        """Analyze recent events"""
        if not events:
            return

        # Count events by type
        event_types = {}
        for event in events:
            alert_type = event.get('alert_type', 'info')
            event_types[alert_type] = event_types.get(alert_type, 0) + 1

        # Check for error events
        if event_types.get('error', 0) > 0:
            self.insights.append(AnalysisInsight(
                category='anomaly',
                severity='warning',
                title='Recent Error Events',
                description=f"{event_types.get('error')} error events in the monitored period",
                metric_value=event_types.get('error')
            ))

    def _analyze_tags(self, tags: List[str]) -> None:
        """Analyze host tags for insights"""
        if not tags:
            return

        # Extract environment
        for tag in tags:
            tag_lower = tag.lower()
            if 'env:' in tag_lower or 'environment:' in tag_lower:
                env = tag.split(':')[-1]
                if env in ['prod', 'production']:
                    self.insights.append(AnalysisInsight(
                        category='info',
                        severity='info',
                        title='Production Environment',
                        description='This server is tagged as production'
                    ))

            # Check for service tags
            if 'service:' in tag_lower:
                service = tag.split(':')[-1]
                if service not in self.server_types:
                    self.server_types.append(f'service:{service}')

    def _detect_patterns(self, metrics: Dict) -> None:
        """Detect patterns in metric data"""
        for metric_name, data in metrics.items():
            values = data.get('values', [])
            if len(values) < 10:
                continue

            # Detect spikes
            avg = sum(values) / len(values)
            max_val = max(values)
            if max_val > avg * self.thresholds['network_spike_multiplier']:
                self.patterns.append(PatternMatch(
                    pattern_type='spike',
                    description=f'Spike detected in {metric_name}: max {max_val:.1f} vs avg {avg:.1f}',
                    metrics_involved=[metric_name],
                    confidence=0.8,
                    metadata={'avg': avg, 'max': max_val, 'spike_ratio': max_val / avg}
                ))

            # Detect trends (simple linear regression)
            trend = self._detect_trend(values)
            if abs(trend) > 0.1:
                direction = 'increasing' if trend > 0 else 'decreasing'
                self.patterns.append(PatternMatch(
                    pattern_type='trend',
                    description=f'{metric_name} is {direction} over time',
                    metrics_involved=[metric_name],
                    confidence=0.7,
                    metadata={'trend_slope': trend, 'direction': direction}
                ))

    def _infer_server_purpose(
        self,
        processes: List[Dict],
        tags: List[str],
        metrics: Dict
    ) -> None:
        """Infer the server's purpose from all available data"""
        # Already partially done in _analyze_processes

        # Additional inference from metrics patterns
        if metrics.get('network_bytes_in', {}).get('avg', 0) > 50_000_000:  # 50MB/s
            if 'load_balancer' not in self.server_types:
                self.server_types.append('high_traffic')

        # If no types detected, mark as general purpose
        if not self.server_types:
            self.server_types.append('general_purpose')

    def _generate_recommendations(self) -> None:
        """Generate actionable recommendations based on analysis"""
        # Check for cost optimization opportunities
        cpu_insights = [i for i in self.insights if i.metric_name == 'cpu']
        mem_insights = [i for i in self.insights if i.metric_name == 'memory']

        low_cpu = any(i.severity == 'info' and 'underutilized' in i.title.lower() for i in cpu_insights)
        low_mem = any(i.severity == 'info' and 'underutilized' in i.title.lower() for i in mem_insights)

        if low_cpu and low_mem:
            self.insights.append(AnalysisInsight(
                category='recommendation',
                severity='info',
                title='Cost Optimization Opportunity',
                description='Both CPU and memory are underutilized. Consider downsizing this server.',
                suggested_action='Evaluate moving to a smaller instance type to reduce costs by 30-50%'
            ))

    def _calculate_health_score(self) -> int:
        """Calculate overall health score (0-100)"""
        score = 100

        for insight in self.insights:
            if insight.severity == 'critical':
                score -= 25
            elif insight.severity == 'warning':
                score -= 10

        return max(0, min(100, score))

    def _generate_summary(self, metrics: Dict) -> Dict[str, Any]:
        """Generate a summary of the analysis"""
        critical_count = sum(1 for i in self.insights if i.severity == 'critical')
        warning_count = sum(1 for i in self.insights if i.severity == 'warning')

        return {
            'server_types': self.server_types,
            'critical_issues': critical_count,
            'warnings': warning_count,
            'patterns_detected': len(self.patterns),
            'overall_assessment': self._get_overall_assessment()
        }

    def _get_overall_assessment(self) -> str:
        """Get overall assessment text"""
        critical = sum(1 for i in self.insights if i.severity == 'critical')
        warnings = sum(1 for i in self.insights if i.severity == 'warning')

        if critical > 0:
            return 'Critical issues detected requiring immediate attention'
        elif warnings > 2:
            return 'Multiple performance concerns identified'
        elif warnings > 0:
            return 'Minor issues detected, generally healthy'
        else:
            return 'System appears healthy'

    def _get_recommendations(self) -> List[str]:
        """Get list of recommendations"""
        return [i.suggested_action for i in self.insights
                if i.suggested_action and i.category == 'recommendation']

    def _get_metric_analysis(self, metrics: Dict) -> Dict[str, Dict]:
        """Get detailed metric analysis"""
        analysis = {}

        for metric_name, data in metrics.items():
            analysis[metric_name] = {
                'avg': round(data.get('avg', 0), 2),
                'min': round(data.get('min', 0), 2),
                'max': round(data.get('max', 0), 2),
                'sample_count': data.get('sample_count', 0)
            }

        return analysis

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate coefficient of variation"""
        if not values or len(values) < 2:
            return 0.0

        avg = sum(values) / len(values)
        if avg == 0:
            return 0.0

        variance = sum((x - avg) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5

        return std_dev / avg  # Coefficient of variation

    def _detect_trend(self, values: List[float]) -> float:
        """Detect trend using simple linear regression slope"""
        if not values or len(values) < 2:
            return 0.0

        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n

        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return 0.0

        slope = numerator / denominator
        # Normalize by mean to get relative trend
        return slope / y_mean if y_mean != 0 else 0.0

    @staticmethod
    def _insight_to_dict(insight: AnalysisInsight) -> Dict:
        """Convert insight to dictionary"""
        return {
            'category': insight.category,
            'severity': insight.severity,
            'title': insight.title,
            'description': insight.description,
            'metric_name': insight.metric_name,
            'metric_value': insight.metric_value,
            'threshold': insight.threshold,
            'suggested_action': insight.suggested_action,
            'confidence': insight.confidence
        }

    @staticmethod
    def _pattern_to_dict(pattern: PatternMatch) -> Dict:
        """Convert pattern to dictionary"""
        return {
            'pattern_type': pattern.pattern_type,
            'description': pattern.description,
            'metrics_involved': pattern.metrics_involved,
            'confidence': pattern.confidence,
            'is_novel': pattern.is_novel,
            'metadata': pattern.metadata
        }
