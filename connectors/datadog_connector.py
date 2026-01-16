"""
Datadog Connector
Connects to Datadog API to fetch server metrics and monitoring data
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available")


class DatadogConfig:
    """Configuration for Datadog API connection"""

    def __init__(
        self,
        api_key: str,
        app_key: str,
        site: str = "datadoghq.com",
        timeout: int = 30
    ):
        """
        Initialize Datadog configuration.

        Args:
            api_key: Datadog API key
            app_key: Datadog Application key
            site: Datadog site (datadoghq.com, datadoghq.eu, us3.datadoghq.com, etc.)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.app_key = app_key
        self.site = site
        self.timeout = timeout

    @property
    def base_url(self) -> str:
        """Get the base URL for API requests"""
        return f"https://api.{self.site}"


class DatadogConnector:
    """Connects to Datadog API to fetch server metrics and data"""

    # Metric queries for common system metrics
    SYSTEM_METRICS = {
        'cpu': {
            'query': 'avg:system.cpu.user{{host:{host}}} + avg:system.cpu.system{{host:{host}}}',
            'description': 'CPU Usage (%)'
        },
        'cpu_user': {
            'query': 'avg:system.cpu.user{{host:{host}}}',
            'description': 'User CPU (%)'
        },
        'cpu_system': {
            'query': 'avg:system.cpu.system{{host:{host}}}',
            'description': 'System CPU (%)'
        },
        'cpu_iowait': {
            'query': 'avg:system.cpu.iowait{{host:{host}}}',
            'description': 'I/O Wait CPU (%)'
        },
        'memory_used': {
            'query': 'avg:system.mem.used{{host:{host}}}',
            'description': 'Memory Used (bytes)'
        },
        'memory_total': {
            'query': 'avg:system.mem.total{{host:{host}}}',
            'description': 'Memory Total (bytes)'
        },
        'memory_pct': {
            'query': 'avg:system.mem.pct_usable{{host:{host}}}',
            'description': 'Memory Usable (%)'
        },
        'load_1': {
            'query': 'avg:system.load.1{{host:{host}}}',
            'description': 'Load Average (1 min)'
        },
        'load_5': {
            'query': 'avg:system.load.5{{host:{host}}}',
            'description': 'Load Average (5 min)'
        },
        'load_15': {
            'query': 'avg:system.load.15{{host:{host}}}',
            'description': 'Load Average (15 min)'
        },
        'disk_used': {
            'query': 'avg:system.disk.used{{host:{host}}}',
            'description': 'Disk Used (bytes)'
        },
        'disk_total': {
            'query': 'avg:system.disk.total{{host:{host}}}',
            'description': 'Disk Total (bytes)'
        },
        'disk_in_use': {
            'query': 'avg:system.disk.in_use{{host:{host}}}',
            'description': 'Disk In Use (%)'
        },
        'disk_read': {
            'query': 'avg:system.io.r_s{{host:{host}}}',
            'description': 'Disk Reads/sec'
        },
        'disk_write': {
            'query': 'avg:system.io.w_s{{host:{host}}}',
            'description': 'Disk Writes/sec'
        },
        'network_bytes_in': {
            'query': 'avg:system.net.bytes_rcvd{{host:{host}}}',
            'description': 'Network Bytes In/sec'
        },
        'network_bytes_out': {
            'query': 'avg:system.net.bytes_sent{{host:{host}}}',
            'description': 'Network Bytes Out/sec'
        },
        'process_count': {
            'query': 'avg:system.proc.count{{host:{host}}}',
            'description': 'Process Count'
        },
    }

    def __init__(self, config: DatadogConfig):
        """
        Initialize Datadog connector.

        Args:
            config: DatadogConfig with API credentials
        """
        self.config = config
        self.headers = {
            'DD-API-KEY': config.api_key,
            'DD-APPLICATION-KEY': config.app_key,
            'Content-Type': 'application/json'
        }
        self._host_info_cache: Dict[str, Any] = {}

    def _api_get(self, endpoint: str, params: Dict = None) -> Optional[Any]:
        """Make GET request to Datadog API"""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library required for Datadog API")
            return None

        try:
            url = f"{self.config.base_url}/{endpoint}"
            response = requests.get(
                url,
                headers=self.headers,
                params=params or {},
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Datadog API error for {endpoint}: {e}")
            return None

    def _api_post(self, endpoint: str, data: Dict) -> Optional[Any]:
        """Make POST request to Datadog API"""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library required for Datadog API")
            return None

        try:
            url = f"{self.config.base_url}/{endpoint}"
            response = requests.post(
                url,
                headers=self.headers,
                json=data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Datadog API error for {endpoint}: {e}")
            return None

    def test_connection(self) -> bool:
        """Test the Datadog API connection"""
        result = self._api_get('api/v1/validate')
        return result is not None and result.get('valid', False)

    def search_hosts(self, query: str = None, filter_str: str = None) -> List[Dict]:
        """
        Search for hosts in Datadog.

        Args:
            query: Search query string
            filter_str: Filter string (e.g., "host:myserver")

        Returns:
            List of host information dictionaries
        """
        params = {}
        if query:
            params['filter'] = query
        if filter_str:
            params['filter'] = filter_str

        result = self._api_get('api/v1/hosts', params)
        if result and 'host_list' in result:
            return result['host_list']
        return []

    def get_host_info(self, hostname: str) -> Optional[Dict]:
        """
        Get detailed information about a specific host.

        Args:
            hostname: The hostname to look up

        Returns:
            Host information dictionary or None
        """
        if hostname in self._host_info_cache:
            return self._host_info_cache[hostname]

        hosts = self.search_hosts(filter_str=f"host:{hostname}")
        for host in hosts:
            if host.get('name') == hostname or hostname in host.get('aliases', []):
                self._host_info_cache[hostname] = host
                return host

        # Try partial match
        hosts = self.search_hosts(query=hostname)
        for host in hosts:
            if hostname.lower() in host.get('name', '').lower():
                self._host_info_cache[hostname] = host
                return host

        return None

    def get_host_tags(self, hostname: str) -> List[str]:
        """Get tags for a specific host"""
        host_info = self.get_host_info(hostname)
        if host_info:
            return host_info.get('tags_by_source', {}).get('Datadog', [])
        return []

    def query_metrics(
        self,
        query: str,
        from_time: int = None,
        to_time: int = None
    ) -> Optional[Dict]:
        """
        Query metrics from Datadog.

        Args:
            query: Datadog metric query string
            from_time: Start time (Unix timestamp)
            to_time: End time (Unix timestamp)

        Returns:
            Metric data dictionary
        """
        if not from_time:
            from_time = int((datetime.now() - timedelta(hours=1)).timestamp())
        if not to_time:
            to_time = int(datetime.now().timestamp())

        params = {
            'query': query,
            'from': from_time,
            'to': to_time
        }

        return self._api_get('api/v1/query', params)

    def get_system_metrics(
        self,
        hostname: str,
        lookback_hours: int = 24,
        metrics: List[str] = None
    ) -> Dict[str, Any]:
        """
        Get system metrics for a host over a time period.

        Args:
            hostname: The hostname to query
            lookback_hours: How many hours to look back
            metrics: List of metric names to fetch (defaults to all)

        Returns:
            Dictionary of metric data with statistics
        """
        from_time = int((datetime.now() - timedelta(hours=lookback_hours)).timestamp())
        to_time = int(datetime.now().timestamp())

        if metrics is None:
            metrics = list(self.SYSTEM_METRICS.keys())

        results = {}
        for metric_name in metrics:
            if metric_name not in self.SYSTEM_METRICS:
                continue

            metric_info = self.SYSTEM_METRICS[metric_name]
            query = metric_info['query'].format(host=hostname)

            data = self.query_metrics(query, from_time, to_time)
            if data and 'series' in data and data['series']:
                series = data['series'][0]
                pointlist = series.get('pointlist', [])

                if pointlist:
                    values = [p[1] for p in pointlist if p[1] is not None]
                    if values:
                        results[metric_name] = {
                            'description': metric_info['description'],
                            'values': values,
                            'timestamps': [p[0] for p in pointlist],
                            'min': min(values),
                            'max': max(values),
                            'avg': sum(values) / len(values),
                            'latest': values[-1] if values else None,
                            'sample_count': len(values)
                        }

        return results

    def get_processes(self, hostname: str, limit: int = 50) -> List[Dict]:
        """
        Get running processes for a host.

        Args:
            hostname: The hostname to query
            limit: Maximum number of processes to return

        Returns:
            List of process information
        """
        # Use the live processes endpoint
        data = {
            'data': {
                'type': 'process_query',
                'attributes': {
                    'query': f'host:{hostname}',
                    'page': {
                        'limit': limit
                    }
                }
            }
        }

        result = self._api_post('api/v2/processes', data)
        if result and 'data' in result:
            processes = []
            for proc in result.get('data', []):
                attrs = proc.get('attributes', {})
                processes.append({
                    'name': attrs.get('cmdline', [''])[0] if attrs.get('cmdline') else '',
                    'pid': attrs.get('pid'),
                    'user': attrs.get('user'),
                    'cpu_percent': attrs.get('cpu', {}).get('pct', 0) * 100,
                    'memory_percent': attrs.get('memory', {}).get('rss', 0),
                    'cmdline': ' '.join(attrs.get('cmdline', [])),
                    'state': attrs.get('state', '')
                })
            return processes
        return []

    def get_active_monitors(self, hostname: str = None) -> List[Dict]:
        """
        Get monitors (alerts) for a host or all monitors.

        Args:
            hostname: Optional hostname to filter by

        Returns:
            List of monitor information
        """
        params = {}
        if hostname:
            params['host_tags'] = hostname

        result = self._api_get('api/v1/monitor', params)
        if result:
            monitors = []
            for monitor in result:
                # Filter by hostname if specified
                if hostname:
                    query = monitor.get('query', '')
                    if hostname not in query:
                        continue

                monitors.append({
                    'id': monitor.get('id'),
                    'name': monitor.get('name'),
                    'type': monitor.get('type'),
                    'query': monitor.get('query'),
                    'overall_state': monitor.get('overall_state'),
                    'message': monitor.get('message', ''),
                    'tags': monitor.get('tags', []),
                    'created': monitor.get('created'),
                    'modified': monitor.get('modified')
                })
            return monitors
        return []

    def get_events(
        self,
        hostname: str = None,
        lookback_hours: int = 24,
        priority: str = None
    ) -> List[Dict]:
        """
        Get events related to a host.

        Args:
            hostname: Optional hostname to filter by
            lookback_hours: How many hours to look back
            priority: Filter by priority ('normal' or 'low')

        Returns:
            List of events
        """
        from_time = int((datetime.now() - timedelta(hours=lookback_hours)).timestamp())

        params = {
            'start': from_time,
            'end': int(datetime.now().timestamp())
        }

        if hostname:
            params['tags'] = f'host:{hostname}'
        if priority:
            params['priority'] = priority

        result = self._api_get('api/v1/events', params)
        if result and 'events' in result:
            events = []
            for event in result['events']:
                events.append({
                    'id': event.get('id'),
                    'title': event.get('title'),
                    'text': event.get('text'),
                    'priority': event.get('priority'),
                    'source': event.get('source_type_name'),
                    'tags': event.get('tags', []),
                    'timestamp': datetime.fromtimestamp(event.get('date_happened', 0)).isoformat(),
                    'alert_type': event.get('alert_type')
                })
            return events
        return []

    def get_service_checks(self, hostname: str) -> List[Dict]:
        """
        Get service check results for a host.

        Args:
            hostname: The hostname to query

        Returns:
            List of service check results
        """
        # Query recent check results
        params = {'names': f'host:{hostname}'}
        result = self._api_get('api/v1/check_run', params)

        if result:
            checks = []
            for check in result:
                checks.append({
                    'name': check.get('check'),
                    'status': check.get('status'),  # 0=OK, 1=Warning, 2=Critical
                    'message': check.get('message', ''),
                    'tags': check.get('tags', []),
                    'timestamp': check.get('timestamp')
                })
            return checks
        return []

    def get_dashboards(self, search_query: str = None) -> List[Dict]:
        """Get list of dashboards"""
        params = {}
        if search_query:
            params['filter[shared]'] = 'false'

        result = self._api_get('api/v1/dashboard', params)
        if result and 'dashboards' in result:
            return [{
                'id': d.get('id'),
                'title': d.get('title'),
                'description': d.get('description', ''),
                'url': d.get('url'),
                'created_at': d.get('created_at'),
                'modified_at': d.get('modified_at')
            } for d in result['dashboards']]
        return []

    def get_all_data_for_host(
        self,
        hostname: str,
        lookback_hours: int = 24,
        include_processes: bool = True
    ) -> Dict[str, Any]:
        """
        Get comprehensive data for a host from Datadog.

        Args:
            hostname: The hostname to analyze
            lookback_hours: How many hours of data to fetch
            include_processes: Whether to include process data

        Returns:
            Complete data dictionary for the host
        """
        logger.info(f"Fetching Datadog data for host: {hostname}")

        data = {
            'hostname': hostname,
            'source': 'datadog',
            'timestamp': datetime.now().isoformat(),
            'lookback_hours': lookback_hours,
            'host_info': None,
            'tags': [],
            'metrics': {},
            'processes': [],
            'monitors': [],
            'events': [],
            'health_summary': {}
        }

        # Get host info
        host_info = self.get_host_info(hostname)
        if host_info:
            data['host_info'] = {
                'name': host_info.get('name'),
                'aliases': host_info.get('aliases', []),
                'apps': host_info.get('apps', []),
                'sources': host_info.get('sources', []),
                'host_name': host_info.get('host_name'),
                'up': host_info.get('up', False),
                'meta': host_info.get('meta', {}),
                'last_reported_time': host_info.get('last_reported_time')
            }
            data['tags'] = self.get_host_tags(hostname)

        # Get metrics
        data['metrics'] = self.get_system_metrics(hostname, lookback_hours)

        # Get processes if requested
        if include_processes:
            data['processes'] = self.get_processes(hostname)

        # Get monitors
        data['monitors'] = self.get_active_monitors(hostname)

        # Get events
        data['events'] = self.get_events(hostname, lookback_hours)

        # Generate health summary
        data['health_summary'] = self._generate_health_summary(data)

        return data

    def _generate_health_summary(self, data: Dict) -> Dict[str, Any]:
        """Generate a health summary from collected data"""
        summary = {
            'status': 'unknown',
            'issues': [],
            'healthy_metrics': [],
            'metric_summary': {}
        }

        metrics = data.get('metrics', {})

        # Check CPU
        if 'cpu' in metrics:
            cpu_avg = metrics['cpu'].get('avg', 0)
            cpu_max = metrics['cpu'].get('max', 0)
            summary['metric_summary']['cpu_avg'] = round(cpu_avg, 1)
            summary['metric_summary']['cpu_max'] = round(cpu_max, 1)

            if cpu_avg > 80:
                summary['issues'].append('High average CPU usage')
            elif cpu_avg < 50:
                summary['healthy_metrics'].append('CPU usage is healthy')

        # Check Memory
        if 'memory_pct' in metrics:
            mem_pct = 100 - (metrics['memory_pct'].get('avg', 100) * 100)
            summary['metric_summary']['memory_used_pct'] = round(mem_pct, 1)

            if mem_pct > 85:
                summary['issues'].append('High memory usage')
            elif mem_pct < 70:
                summary['healthy_metrics'].append('Memory usage is healthy')

        # Check Load
        if 'load_1' in metrics:
            load = metrics['load_1'].get('avg', 0)
            summary['metric_summary']['load_avg'] = round(load, 2)

            if load > 4:
                summary['issues'].append('High system load')

        # Check Disk
        if 'disk_in_use' in metrics:
            disk_pct = metrics['disk_in_use'].get('avg', 0) * 100
            summary['metric_summary']['disk_used_pct'] = round(disk_pct, 1)

            if disk_pct > 85:
                summary['issues'].append('High disk usage')

        # Check monitors
        monitors = data.get('monitors', [])
        alert_count = sum(1 for m in monitors if m.get('overall_state') == 'Alert')
        warn_count = sum(1 for m in monitors if m.get('overall_state') == 'Warn')

        summary['metric_summary']['alert_count'] = alert_count
        summary['metric_summary']['warning_count'] = warn_count

        if alert_count > 0:
            summary['issues'].append(f'{alert_count} active alert(s)')
        if warn_count > 0:
            summary['issues'].append(f'{warn_count} warning(s)')

        # Determine overall status
        if not summary['issues']:
            summary['status'] = 'healthy'
        elif any('High' in issue or 'alert' in issue.lower() for issue in summary['issues']):
            summary['status'] = 'critical' if len(summary['issues']) > 2 else 'warning'
        else:
            summary['status'] = 'warning'

        return summary
