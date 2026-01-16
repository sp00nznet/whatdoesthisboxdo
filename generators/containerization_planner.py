"""
Containerization Planner
Generates container configurations based on Datadog metrics and application profiling.
Creates Dockerfiles, docker-compose.yml, and Kubernetes manifests with scaling strategies.
"""

import json
import logging
import math
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ApplicationProfile:
    """Profile of an application identified from metrics"""
    name: str
    app_type: str  # web, database, cache, queue, worker, etc.
    processes: List[str]
    ports: List[int]
    cpu_avg: float
    cpu_max: float
    memory_avg_mb: float
    memory_max_mb: float
    network_in_mbps: float
    network_out_mbps: float
    disk_read_mbps: float
    disk_write_mbps: float
    is_stateful: bool = False
    requires_persistence: bool = False
    dependencies: List[str] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    config_files: List[str] = field(default_factory=list)
    scaling_profile: str = 'horizontal'  # horizontal, vertical, or none
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScalingRecommendation:
    """Scaling recommendation for an application"""
    strategy: str  # horizontal, vertical, hybrid
    min_replicas: int
    max_replicas: int
    target_cpu_percent: int
    target_memory_percent: int
    scale_up_threshold: float
    scale_down_threshold: float
    cooldown_seconds: int
    reasoning: List[str]
    warnings: List[str] = field(default_factory=list)


# Application detection patterns
APP_SIGNATURES = {
    'nginx': {
        'type': 'web',
        'processes': ['nginx'],
        'ports': [80, 443, 8080],
        'stateful': False,
        'base_image': 'nginx:alpine',
        'scaling': 'horizontal',
    },
    'apache': {
        'type': 'web',
        'processes': ['httpd', 'apache2'],
        'ports': [80, 443, 8080],
        'stateful': False,
        'base_image': 'httpd:alpine',
        'scaling': 'horizontal',
    },
    'nodejs': {
        'type': 'web',
        'processes': ['node', 'npm', 'yarn'],
        'ports': [3000, 8080, 5000],
        'stateful': False,
        'base_image': 'node:20-alpine',
        'scaling': 'horizontal',
    },
    'python_web': {
        'type': 'web',
        'processes': ['gunicorn', 'uwsgi', 'uvicorn', 'python'],
        'ports': [8000, 5000, 8080],
        'stateful': False,
        'base_image': 'python:3.11-slim',
        'scaling': 'horizontal',
    },
    'java': {
        'type': 'web',
        'processes': ['java', 'tomcat', 'spring'],
        'ports': [8080, 8443],
        'stateful': False,
        'base_image': 'eclipse-temurin:21-jre-alpine',
        'scaling': 'horizontal',
    },
    'postgresql': {
        'type': 'database',
        'processes': ['postgres', 'postgresql'],
        'ports': [5432],
        'stateful': True,
        'base_image': 'postgres:16-alpine',
        'scaling': 'vertical',
    },
    'mysql': {
        'type': 'database',
        'processes': ['mysqld', 'mysql', 'mariadb'],
        'ports': [3306],
        'stateful': True,
        'base_image': 'mysql:8',
        'scaling': 'vertical',
    },
    'mongodb': {
        'type': 'database',
        'processes': ['mongod', 'mongodb'],
        'ports': [27017],
        'stateful': True,
        'base_image': 'mongo:7',
        'scaling': 'horizontal',  # Can shard
    },
    'redis': {
        'type': 'cache',
        'processes': ['redis-server', 'redis'],
        'ports': [6379],
        'stateful': False,  # Can be stateless for caching
        'base_image': 'redis:7-alpine',
        'scaling': 'horizontal',
    },
    'memcached': {
        'type': 'cache',
        'processes': ['memcached'],
        'ports': [11211],
        'stateful': False,
        'base_image': 'memcached:alpine',
        'scaling': 'horizontal',
    },
    'rabbitmq': {
        'type': 'queue',
        'processes': ['rabbitmq', 'beam.smp'],
        'ports': [5672, 15672],
        'stateful': True,
        'base_image': 'rabbitmq:3-management-alpine',
        'scaling': 'horizontal',
    },
    'kafka': {
        'type': 'queue',
        'processes': ['kafka', 'java'],
        'ports': [9092],
        'stateful': True,
        'base_image': 'confluentinc/cp-kafka:latest',
        'scaling': 'horizontal',
    },
    'elasticsearch': {
        'type': 'search',
        'processes': ['elasticsearch', 'java'],
        'ports': [9200, 9300],
        'stateful': True,
        'base_image': 'elasticsearch:8.11.0',
        'scaling': 'horizontal',
    },
    'celery': {
        'type': 'worker',
        'processes': ['celery'],
        'ports': [],
        'stateful': False,
        'base_image': 'python:3.11-slim',
        'scaling': 'horizontal',
    },
    'sidekiq': {
        'type': 'worker',
        'processes': ['sidekiq'],
        'ports': [],
        'stateful': False,
        'base_image': 'ruby:3.2-alpine',
        'scaling': 'horizontal',
    },
}


class ContainerizationPlanner:
    """
    Plans containerization strategy based on Datadog metrics and analysis.
    Generates Dockerfiles, docker-compose, and Kubernetes configurations.
    """

    def __init__(self, datadog_data: Dict[str, Any], analysis_results: Dict[str, Any] = None):
        """
        Initialize planner with Datadog data and optional analysis results.

        Args:
            datadog_data: Raw data from DatadogConnector.get_all_data_for_host()
            analysis_results: Results from DatadogAnalyzer.analyze()
        """
        self.datadog_data = datadog_data
        self.analysis_results = analysis_results or {}
        self.hostname = datadog_data.get('hostname', 'unknown')
        self.applications: List[ApplicationProfile] = []
        self.scaling_recommendations: Dict[str, ScalingRecommendation] = {}

    def analyze_and_plan(self) -> Dict[str, Any]:
        """
        Perform full analysis and generate containerization plan.

        Returns:
            Complete containerization plan with all configurations
        """
        logger.info(f"Creating containerization plan for {self.hostname}")

        # Step 1: Profile applications
        self._profile_applications()

        # Step 2: Calculate resource requirements
        self._calculate_resource_requirements()

        # Step 3: Generate scaling recommendations
        self._generate_scaling_recommendations()

        # Step 4: Generate configurations
        dockerfiles = self._generate_dockerfiles()
        docker_compose = self._generate_docker_compose()
        kubernetes = self._generate_kubernetes_manifests()

        return {
            'hostname': self.hostname,
            'generated_at': datetime.now().isoformat(),
            'applications': [self._profile_to_dict(app) for app in self.applications],
            'scaling_recommendations': {
                name: self._recommendation_to_dict(rec)
                for name, rec in self.scaling_recommendations.items()
            },
            'configurations': {
                'dockerfiles': dockerfiles,
                'docker_compose': docker_compose,
                'kubernetes': kubernetes
            },
            'summary': self._generate_summary()
        }

    def _profile_applications(self) -> None:
        """Identify and profile applications from Datadog data"""
        processes = self.datadog_data.get('processes', [])
        metrics = self.datadog_data.get('metrics', {})
        tags = self.datadog_data.get('tags', [])

        # Extract process names
        process_names = set()
        for proc in processes:
            name = proc.get('name', '').lower()
            cmdline = proc.get('cmdline', '').lower()
            if name:
                process_names.add(name)
            # Also check command line for framework detection
            for keyword in ['gunicorn', 'uvicorn', 'celery', 'sidekiq', 'node', 'java']:
                if keyword in cmdline:
                    process_names.add(keyword)

        # Match against known application signatures
        detected_apps = {}
        for app_name, signature in APP_SIGNATURES.items():
            for sig_proc in signature['processes']:
                if any(sig_proc in pname for pname in process_names):
                    if app_name not in detected_apps:
                        detected_apps[app_name] = signature
                    break

        # If no specific apps detected, create generic profile
        if not detected_apps:
            detected_apps['generic_app'] = {
                'type': 'web',
                'processes': list(process_names)[:5],
                'ports': [8080],
                'stateful': False,
                'base_image': 'ubuntu:22.04',
                'scaling': 'horizontal',
            }

        # Create application profiles with metrics
        cpu_data = metrics.get('cpu', metrics.get('cpu_user', {}))
        mem_data = metrics.get('memory_used', {})
        mem_total = metrics.get('memory_total', {}).get('avg', 8 * 1024 * 1024 * 1024)  # Default 8GB
        net_in = metrics.get('network_bytes_in', {})
        net_out = metrics.get('network_bytes_out', {})
        disk_read = metrics.get('disk_read', {})
        disk_write = metrics.get('disk_write', {})

        for app_name, signature in detected_apps.items():
            # Calculate per-app estimates (divide by number of detected apps)
            app_count = len(detected_apps)

            profile = ApplicationProfile(
                name=app_name,
                app_type=signature['type'],
                processes=signature['processes'],
                ports=signature['ports'],
                cpu_avg=cpu_data.get('avg', 10) / app_count,
                cpu_max=cpu_data.get('max', 50) / app_count,
                memory_avg_mb=(mem_data.get('avg', 1024 * 1024 * 1024) / (1024 * 1024)) / app_count,
                memory_max_mb=(mem_data.get('max', 2 * 1024 * 1024 * 1024) / (1024 * 1024)) / app_count,
                network_in_mbps=(net_in.get('avg', 0) / 1_000_000) / app_count,
                network_out_mbps=(net_out.get('avg', 0) / 1_000_000) / app_count,
                disk_read_mbps=(disk_read.get('avg', 0) / 1_000_000) / app_count,
                disk_write_mbps=(disk_write.get('avg', 0) / 1_000_000) / app_count,
                is_stateful=signature['stateful'],
                requires_persistence=signature['stateful'],
                scaling_profile=signature['scaling'],
                metadata={
                    'base_image': signature['base_image'],
                    'detected_from': 'datadog_metrics'
                }
            )

            self.applications.append(profile)

        logger.info(f"Identified {len(self.applications)} applications")

    def _calculate_resource_requirements(self) -> None:
        """Calculate container resource requirements based on metrics"""
        for app in self.applications:
            # Calculate recommended container resources with headroom
            headroom = 1.3  # 30% headroom

            # CPU: Convert percentage to millicores (assuming 4 cores)
            cpu_request = max(100, int((app.cpu_avg / 100) * 4000 * headroom))
            cpu_limit = max(200, int((app.cpu_max / 100) * 4000 * headroom))

            # Memory: Add headroom
            mem_request = max(128, int(app.memory_avg_mb * headroom))
            mem_limit = max(256, int(app.memory_max_mb * headroom))

            # Round to nice numbers
            cpu_request = self._round_to_nice_number(cpu_request, [100, 250, 500, 1000, 2000, 4000])
            cpu_limit = self._round_to_nice_number(cpu_limit, [250, 500, 1000, 2000, 4000, 8000])
            mem_request = self._round_to_nice_number(mem_request, [128, 256, 512, 1024, 2048, 4096, 8192])
            mem_limit = self._round_to_nice_number(mem_limit, [256, 512, 1024, 2048, 4096, 8192, 16384])

            app.metadata['resources'] = {
                'cpu_request_millicores': cpu_request,
                'cpu_limit_millicores': cpu_limit,
                'memory_request_mb': mem_request,
                'memory_limit_mb': mem_limit
            }

    def _round_to_nice_number(self, value: float, nice_numbers: List[int]) -> int:
        """Round value to nearest 'nice' number from list"""
        for nice in nice_numbers:
            if value <= nice:
                return nice
        return nice_numbers[-1]

    def _generate_scaling_recommendations(self) -> None:
        """Generate scaling recommendations for each application"""
        for app in self.applications:
            reasoning = []
            warnings = []

            # Determine strategy based on app type and metrics
            if app.is_stateful and app.app_type == 'database':
                strategy = 'vertical'
                min_replicas = 1
                max_replicas = 1
                reasoning.append(f"{app.name} is a stateful database - vertical scaling recommended")
                warnings.append("Consider using managed database service for production")
            elif app.scaling_profile == 'vertical':
                strategy = 'vertical'
                min_replicas = 1
                max_replicas = 3
                reasoning.append(f"{app.name} benefits from vertical scaling")
            else:
                strategy = 'horizontal'

                # Calculate replica count based on load
                if app.cpu_avg > 60:
                    min_replicas = max(2, int(app.cpu_avg / 30))
                    reasoning.append(f"High CPU usage ({app.cpu_avg:.1f}%) suggests multiple replicas")
                elif app.cpu_avg > 30:
                    min_replicas = 2
                    reasoning.append("Moderate load - start with 2 replicas for redundancy")
                else:
                    min_replicas = 1
                    reasoning.append("Low load - single replica sufficient")

                # Max replicas based on peak load
                if app.cpu_max > 80:
                    max_replicas = max(min_replicas * 3, int(app.cpu_max / 20))
                    reasoning.append(f"CPU spikes to {app.cpu_max:.1f}% - allow scaling to {max_replicas} replicas")
                else:
                    max_replicas = max(min_replicas * 2, 4)

            # Calculate thresholds
            target_cpu = 70 if strategy == 'horizontal' else 80
            target_memory = 75 if strategy == 'horizontal' else 85

            # Check for bursty workloads
            if hasattr(app, 'cpu_max') and app.cpu_max > app.cpu_avg * 2:
                warnings.append("Bursty workload detected - consider pre-warming or scheduled scaling")
                reasoning.append("High variance in CPU usage indicates bursty traffic patterns")

            recommendation = ScalingRecommendation(
                strategy=strategy,
                min_replicas=min_replicas,
                max_replicas=max_replicas,
                target_cpu_percent=target_cpu,
                target_memory_percent=target_memory,
                scale_up_threshold=target_cpu * 0.9,
                scale_down_threshold=target_cpu * 0.5,
                cooldown_seconds=300 if strategy == 'horizontal' else 600,
                reasoning=reasoning,
                warnings=warnings
            )

            self.scaling_recommendations[app.name] = recommendation

    def _generate_dockerfiles(self) -> Dict[str, str]:
        """Generate Dockerfiles for each application"""
        dockerfiles = {}

        for app in self.applications:
            base_image = app.metadata.get('base_image', 'ubuntu:22.04')
            dockerfile = self._create_dockerfile(app, base_image)
            dockerfiles[app.name] = dockerfile

        return dockerfiles

    def _create_dockerfile(self, app: ApplicationProfile, base_image: str) -> str:
        """Create a Dockerfile for an application"""
        lines = [
            f"# Dockerfile for {app.name}",
            f"# Generated by WhatDoesThisBoxDo Containerization Planner",
            f"# Based on Datadog metrics analysis",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            f"FROM {base_image}",
            "",
            "# Labels",
            f'LABEL maintainer="devops@example.com"',
            f'LABEL app.name="{app.name}"',
            f'LABEL app.type="{app.app_type}"',
            "",
        ]

        # Add app-specific configurations
        if app.app_type == 'web':
            lines.extend(self._dockerfile_web_app(app, base_image))
        elif app.app_type == 'database':
            lines.extend(self._dockerfile_database(app, base_image))
        elif app.app_type == 'cache':
            lines.extend(self._dockerfile_cache(app, base_image))
        elif app.app_type == 'queue':
            lines.extend(self._dockerfile_queue(app, base_image))
        elif app.app_type == 'worker':
            lines.extend(self._dockerfile_worker(app, base_image))
        else:
            lines.extend(self._dockerfile_generic(app, base_image))

        # Add health check
        if app.ports:
            port = app.ports[0]
            lines.extend([
                "",
                "# Health check",
                f"HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\",
                f"  CMD curl -f http://localhost:{port}/health || exit 1",
            ])

        # Expose ports
        if app.ports:
            lines.extend([
                "",
                "# Expose ports",
            ])
            for port in app.ports:
                lines.append(f"EXPOSE {port}")

        return '\n'.join(lines)

    def _dockerfile_web_app(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate Dockerfile lines for web applications"""
        lines = []

        if 'node' in base_image:
            lines = [
                "# Node.js application",
                "WORKDIR /app",
                "",
                "# Install dependencies first (for layer caching)",
                "COPY package*.json ./",
                "RUN npm ci --only=production",
                "",
                "# Copy application code",
                "COPY . .",
                "",
                "# Build if needed",
                "RUN npm run build --if-present",
                "",
                "# Run as non-root user",
                "RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001",
                "USER nodejs",
                "",
                "# Start command",
                "CMD [\"node\", \"server.js\"]",
            ]
        elif 'python' in base_image:
            lines = [
                "# Python application",
                "WORKDIR /app",
                "",
                "# Install system dependencies",
                "RUN apt-get update && apt-get install -y --no-install-recommends \\",
                "    curl \\",
                "    && rm -rf /var/lib/apt/lists/*",
                "",
                "# Install Python dependencies",
                "COPY requirements.txt .",
                "RUN pip install --no-cache-dir -r requirements.txt",
                "",
                "# Copy application code",
                "COPY . .",
                "",
                "# Run as non-root user",
                "RUN useradd -m -u 1001 appuser",
                "USER appuser",
                "",
                "# Start command (adjust based on framework)",
                "CMD [\"gunicorn\", \"--bind\", \"0.0.0.0:8000\", \"--workers\", \"4\", \"app:app\"]",
            ]
        elif 'nginx' in base_image:
            lines = [
                "# Nginx web server",
                "",
                "# Copy custom configuration",
                "COPY nginx.conf /etc/nginx/nginx.conf",
                "",
                "# Copy static files",
                "COPY public/ /usr/share/nginx/html/",
                "",
                "# Start nginx",
                "CMD [\"nginx\", \"-g\", \"daemon off;\"]",
            ]
        elif 'java' in base_image or 'temurin' in base_image:
            lines = [
                "# Java application",
                "WORKDIR /app",
                "",
                "# Copy JAR file",
                "COPY target/*.jar app.jar",
                "",
                "# JVM memory settings (adjust based on container limits)",
                "ENV JAVA_OPTS=\"-Xms256m -Xmx512m -XX:+UseG1GC\"",
                "",
                "# Run as non-root user",
                "RUN addgroup --system --gid 1001 javauser && \\",
                "    adduser --system --uid 1001 --gid 1001 javauser",
                "USER javauser",
                "",
                "# Start command",
                'ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]',
            ]
        else:
            lines = [
                "# Generic web application",
                "WORKDIR /app",
                "COPY . .",
                "CMD [\"./start.sh\"]",
            ]

        return lines

    def _dockerfile_database(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate Dockerfile lines for databases"""
        lines = [
            "# Database configuration",
            "# Note: For production, use managed database services when possible",
            "",
        ]

        if 'postgres' in base_image:
            lines.extend([
                "# PostgreSQL customizations",
                "COPY postgresql.conf /etc/postgresql/postgresql.conf",
                "COPY init-scripts/ /docker-entrypoint-initdb.d/",
                "",
                "# Performance tuning based on metrics",
                f"# Recommended shared_buffers: {int(app.memory_avg_mb * 0.25)}MB",
                f"# Recommended effective_cache_size: {int(app.memory_avg_mb * 0.75)}MB",
            ])
        elif 'mysql' in base_image:
            lines.extend([
                "# MySQL customizations",
                "COPY my.cnf /etc/mysql/conf.d/custom.cnf",
                "COPY init-scripts/ /docker-entrypoint-initdb.d/",
                "",
                "# Performance tuning based on metrics",
                f"# Recommended innodb_buffer_pool_size: {int(app.memory_avg_mb * 0.7)}MB",
            ])
        elif 'mongo' in base_image:
            lines.extend([
                "# MongoDB customizations",
                "COPY mongod.conf /etc/mongod.conf",
                "",
                "# WiredTiger cache size recommendation",
                f"# Recommended cacheSizeGB: {max(0.25, app.memory_avg_mb / 1024 * 0.5):.2f}",
            ])

        return lines

    def _dockerfile_cache(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate Dockerfile lines for cache servers"""
        lines = []

        if 'redis' in base_image:
            lines = [
                "# Redis configuration",
                "COPY redis.conf /usr/local/etc/redis/redis.conf",
                "",
                f"# Recommended maxmemory: {int(app.memory_avg_mb * 0.8)}mb",
                "# Recommended maxmemory-policy: allkeys-lru",
                "",
                'CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]',
            ]
        elif 'memcached' in base_image:
            mem_mb = int(app.memory_avg_mb * 0.9)
            lines = [
                "# Memcached configuration",
                f'CMD ["memcached", "-m", "{mem_mb}"]',
            ]

        return lines

    def _dockerfile_queue(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate Dockerfile lines for message queues"""
        lines = [
            "# Message queue configuration",
            "",
        ]

        if 'rabbitmq' in base_image:
            lines.extend([
                "# RabbitMQ plugins",
                "RUN rabbitmq-plugins enable --offline rabbitmq_management rabbitmq_prometheus",
                "",
                "# Custom configuration",
                "COPY rabbitmq.conf /etc/rabbitmq/rabbitmq.conf",
            ])

        return lines

    def _dockerfile_worker(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate Dockerfile lines for worker processes"""
        lines = [
            "# Worker process configuration",
            "WORKDIR /app",
            "",
            "COPY requirements.txt .",
            "RUN pip install --no-cache-dir -r requirements.txt",
            "",
            "COPY . .",
            "",
            "# Run as non-root",
            "RUN useradd -m -u 1001 worker",
            "USER worker",
            "",
        ]

        if 'celery' in app.processes:
            lines.append('CMD ["celery", "-A", "tasks", "worker", "--loglevel=info", "--concurrency=4"]')
        elif 'sidekiq' in app.processes:
            lines.append('CMD ["sidekiq", "-c", "10"]')
        else:
            lines.append('CMD ["python", "worker.py"]')

        return lines

    def _dockerfile_generic(self, app: ApplicationProfile, base_image: str) -> List[str]:
        """Generate generic Dockerfile lines"""
        return [
            "# Generic application",
            "WORKDIR /app",
            "",
            "# Copy application files",
            "COPY . .",
            "",
            "# Install dependencies (customize as needed)",
            "# RUN apt-get update && apt-get install -y <packages>",
            "",
            "# Run as non-root",
            "RUN useradd -m -u 1001 appuser",
            "USER appuser",
            "",
            "# Start command",
            "CMD [\"./start.sh\"]",
        ]

    def _generate_docker_compose(self) -> str:
        """Generate docker-compose.yml for all applications"""
        compose = {
            'version': '3.8',
            'services': {},
            'networks': {
                'app-network': {
                    'driver': 'bridge'
                }
            },
            'volumes': {}
        }

        for app in self.applications:
            service = self._create_compose_service(app)
            compose['services'][app.name] = service

            # Add volume for stateful apps
            if app.requires_persistence:
                volume_name = f"{app.name}-data"
                compose['volumes'][volume_name] = {'driver': 'local'}

        # Convert to YAML-like string (manual for better formatting)
        return self._dict_to_yaml(compose)

    def _create_compose_service(self, app: ApplicationProfile) -> Dict:
        """Create docker-compose service definition"""
        resources = app.metadata.get('resources', {})
        scaling = self.scaling_recommendations.get(app.name)

        service = {
            'build': {
                'context': f'./{app.name}',
                'dockerfile': 'Dockerfile'
            },
            'image': f'{app.name}:latest',
            'container_name': app.name,
            'restart': 'unless-stopped',
            'networks': ['app-network'],
        }

        # Add ports
        if app.ports:
            service['ports'] = [f"{p}:{p}" for p in app.ports]

        # Add resource limits
        service['deploy'] = {
            'resources': {
                'limits': {
                    'cpus': f"{resources.get('cpu_limit_millicores', 1000) / 1000:.1f}",
                    'memory': f"{resources.get('memory_limit_mb', 512)}M"
                },
                'reservations': {
                    'cpus': f"{resources.get('cpu_request_millicores', 250) / 1000:.2f}",
                    'memory': f"{resources.get('memory_request_mb', 256)}M"
                }
            }
        }

        # Add replicas for horizontal scaling
        if scaling and scaling.strategy == 'horizontal':
            service['deploy']['replicas'] = scaling.min_replicas

        # Add volumes for stateful apps
        if app.requires_persistence:
            volume_name = f"{app.name}-data"
            mount_path = self._get_data_mount_path(app)
            service['volumes'] = [f"{volume_name}:{mount_path}"]

        # Add health check
        if app.ports:
            service['healthcheck'] = {
                'test': ['CMD', 'curl', '-f', f'http://localhost:{app.ports[0]}/health'],
                'interval': '30s',
                'timeout': '10s',
                'retries': 3,
                'start_period': '10s'
            }

        # Add environment variables
        service['environment'] = self._get_environment_vars(app)

        return service

    def _get_data_mount_path(self, app: ApplicationProfile) -> str:
        """Get the data mount path for stateful applications"""
        paths = {
            'postgresql': '/var/lib/postgresql/data',
            'mysql': '/var/lib/mysql',
            'mongodb': '/data/db',
            'redis': '/data',
            'rabbitmq': '/var/lib/rabbitmq',
            'elasticsearch': '/usr/share/elasticsearch/data',
        }
        return paths.get(app.name, '/data')

    def _get_environment_vars(self, app: ApplicationProfile) -> Dict[str, str]:
        """Get environment variables for an application"""
        env = {}

        if app.app_type == 'database':
            if 'postgres' in app.name:
                env = {
                    'POSTGRES_USER': '${POSTGRES_USER:-app}',
                    'POSTGRES_PASSWORD': '${POSTGRES_PASSWORD}',
                    'POSTGRES_DB': '${POSTGRES_DB:-app}',
                }
            elif 'mysql' in app.name:
                env = {
                    'MYSQL_ROOT_PASSWORD': '${MYSQL_ROOT_PASSWORD}',
                    'MYSQL_DATABASE': '${MYSQL_DATABASE:-app}',
                    'MYSQL_USER': '${MYSQL_USER:-app}',
                    'MYSQL_PASSWORD': '${MYSQL_PASSWORD}',
                }
            elif 'mongo' in app.name:
                env = {
                    'MONGO_INITDB_ROOT_USERNAME': '${MONGO_USER:-admin}',
                    'MONGO_INITDB_ROOT_PASSWORD': '${MONGO_PASSWORD}',
                }
        elif app.app_type == 'cache':
            if 'redis' in app.name:
                env = {
                    'REDIS_PASSWORD': '${REDIS_PASSWORD:-}',
                }
        elif app.app_type == 'queue':
            if 'rabbitmq' in app.name:
                env = {
                    'RABBITMQ_DEFAULT_USER': '${RABBITMQ_USER:-guest}',
                    'RABBITMQ_DEFAULT_PASS': '${RABBITMQ_PASSWORD:-guest}',
                }
        else:
            env = {
                'NODE_ENV': 'production',
                'LOG_LEVEL': 'info',
            }

        return env

    def _generate_kubernetes_manifests(self) -> Dict[str, str]:
        """Generate Kubernetes manifests for all applications"""
        manifests = {}

        for app in self.applications:
            scaling = self.scaling_recommendations.get(app.name)

            # Generate deployment
            deployment = self._create_k8s_deployment(app, scaling)
            manifests[f'{app.name}-deployment.yaml'] = self._dict_to_yaml(deployment)

            # Generate service
            if app.ports:
                service = self._create_k8s_service(app)
                manifests[f'{app.name}-service.yaml'] = self._dict_to_yaml(service)

            # Generate HPA for horizontal scaling
            if scaling and scaling.strategy == 'horizontal':
                hpa = self._create_k8s_hpa(app, scaling)
                manifests[f'{app.name}-hpa.yaml'] = self._dict_to_yaml(hpa)

            # Generate PVC for stateful apps
            if app.requires_persistence:
                pvc = self._create_k8s_pvc(app)
                manifests[f'{app.name}-pvc.yaml'] = self._dict_to_yaml(pvc)

        # Generate namespace
        namespace = self._create_k8s_namespace()
        manifests['namespace.yaml'] = self._dict_to_yaml(namespace)

        return manifests

    def _create_k8s_namespace(self) -> Dict:
        """Create Kubernetes namespace"""
        return {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': self.hostname.replace('.', '-').lower(),
                'labels': {
                    'app.kubernetes.io/managed-by': 'whatdoesthisboxdo'
                }
            }
        }

    def _create_k8s_deployment(self, app: ApplicationProfile, scaling: ScalingRecommendation) -> Dict:
        """Create Kubernetes Deployment"""
        resources = app.metadata.get('resources', {})

        container = {
            'name': app.name,
            'image': f'{app.name}:latest',
            'imagePullPolicy': 'Always',
            'resources': {
                'requests': {
                    'cpu': f"{resources.get('cpu_request_millicores', 250)}m",
                    'memory': f"{resources.get('memory_request_mb', 256)}Mi"
                },
                'limits': {
                    'cpu': f"{resources.get('cpu_limit_millicores', 1000)}m",
                    'memory': f"{resources.get('memory_limit_mb', 512)}Mi"
                }
            },
            'env': [
                {'name': k, 'value': v} for k, v in self._get_environment_vars(app).items()
            ]
        }

        # Add ports
        if app.ports:
            container['ports'] = [
                {'containerPort': port, 'protocol': 'TCP'} for port in app.ports
            ]

        # Add health probes
        if app.ports:
            port = app.ports[0]
            container['livenessProbe'] = {
                'httpGet': {'path': '/health', 'port': port},
                'initialDelaySeconds': 30,
                'periodSeconds': 10,
                'timeoutSeconds': 5,
                'failureThreshold': 3
            }
            container['readinessProbe'] = {
                'httpGet': {'path': '/ready', 'port': port},
                'initialDelaySeconds': 5,
                'periodSeconds': 5,
                'timeoutSeconds': 3,
                'failureThreshold': 3
            }

        # Add volume mounts for stateful apps
        if app.requires_persistence:
            mount_path = self._get_data_mount_path(app)
            container['volumeMounts'] = [
                {'name': f'{app.name}-storage', 'mountPath': mount_path}
            ]

        deployment = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': app.name,
                'labels': {
                    'app': app.name,
                    'app.kubernetes.io/name': app.name,
                    'app.kubernetes.io/component': app.app_type
                }
            },
            'spec': {
                'replicas': scaling.min_replicas if scaling else 1,
                'selector': {
                    'matchLabels': {'app': app.name}
                },
                'template': {
                    'metadata': {
                        'labels': {
                            'app': app.name,
                            'app.kubernetes.io/name': app.name
                        }
                    },
                    'spec': {
                        'containers': [container]
                    }
                }
            }
        }

        # Add volumes for stateful apps
        if app.requires_persistence:
            deployment['spec']['template']['spec']['volumes'] = [
                {
                    'name': f'{app.name}-storage',
                    'persistentVolumeClaim': {'claimName': f'{app.name}-pvc'}
                }
            ]

        # Add pod anti-affinity for high availability
        if scaling and scaling.min_replicas > 1:
            deployment['spec']['template']['spec']['affinity'] = {
                'podAntiAffinity': {
                    'preferredDuringSchedulingIgnoredDuringExecution': [{
                        'weight': 100,
                        'podAffinityTerm': {
                            'labelSelector': {
                                'matchExpressions': [{
                                    'key': 'app',
                                    'operator': 'In',
                                    'values': [app.name]
                                }]
                            },
                            'topologyKey': 'kubernetes.io/hostname'
                        }
                    }]
                }
            }

        return deployment

    def _create_k8s_service(self, app: ApplicationProfile) -> Dict:
        """Create Kubernetes Service"""
        return {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': app.name,
                'labels': {
                    'app': app.name
                }
            },
            'spec': {
                'selector': {'app': app.name},
                'ports': [
                    {'port': port, 'targetPort': port, 'protocol': 'TCP', 'name': f'port-{port}'}
                    for port in app.ports
                ],
                'type': 'ClusterIP'
            }
        }

    def _create_k8s_hpa(self, app: ApplicationProfile, scaling: ScalingRecommendation) -> Dict:
        """Create Kubernetes HorizontalPodAutoscaler"""
        return {
            'apiVersion': 'autoscaling/v2',
            'kind': 'HorizontalPodAutoscaler',
            'metadata': {
                'name': f'{app.name}-hpa',
                'labels': {'app': app.name}
            },
            'spec': {
                'scaleTargetRef': {
                    'apiVersion': 'apps/v1',
                    'kind': 'Deployment',
                    'name': app.name
                },
                'minReplicas': scaling.min_replicas,
                'maxReplicas': scaling.max_replicas,
                'metrics': [
                    {
                        'type': 'Resource',
                        'resource': {
                            'name': 'cpu',
                            'target': {
                                'type': 'Utilization',
                                'averageUtilization': scaling.target_cpu_percent
                            }
                        }
                    },
                    {
                        'type': 'Resource',
                        'resource': {
                            'name': 'memory',
                            'target': {
                                'type': 'Utilization',
                                'averageUtilization': scaling.target_memory_percent
                            }
                        }
                    }
                ],
                'behavior': {
                    'scaleUp': {
                        'stabilizationWindowSeconds': 60,
                        'policies': [{
                            'type': 'Percent',
                            'value': 100,
                            'periodSeconds': 15
                        }]
                    },
                    'scaleDown': {
                        'stabilizationWindowSeconds': scaling.cooldown_seconds,
                        'policies': [{
                            'type': 'Percent',
                            'value': 10,
                            'periodSeconds': 60
                        }]
                    }
                }
            }
        }

    def _create_k8s_pvc(self, app: ApplicationProfile) -> Dict:
        """Create Kubernetes PersistentVolumeClaim"""
        # Calculate storage size based on disk usage
        storage_gb = max(10, int(app.disk_write_mbps * 3600 * 24 / 1024))  # Rough estimate

        return {
            'apiVersion': 'v1',
            'kind': 'PersistentVolumeClaim',
            'metadata': {
                'name': f'{app.name}-pvc',
                'labels': {'app': app.name}
            },
            'spec': {
                'accessModes': ['ReadWriteOnce'],
                'storageClassName': 'standard',
                'resources': {
                    'requests': {
                        'storage': f'{storage_gb}Gi'
                    }
                }
            }
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of the containerization plan"""
        total_cpu = sum(
            app.metadata.get('resources', {}).get('cpu_request_millicores', 0)
            for app in self.applications
        )
        total_memory = sum(
            app.metadata.get('resources', {}).get('memory_request_mb', 0)
            for app in self.applications
        )

        horizontal_apps = [
            app.name for app in self.applications
            if self.scaling_recommendations.get(app.name, {}) and
            self.scaling_recommendations[app.name].strategy == 'horizontal'
        ]
        stateful_apps = [app.name for app in self.applications if app.is_stateful]

        return {
            'total_applications': len(self.applications),
            'total_cpu_millicores': total_cpu,
            'total_memory_mb': total_memory,
            'horizontal_scaling_apps': horizontal_apps,
            'stateful_apps': stateful_apps,
            'recommendations': self._get_top_recommendations()
        }

    def _get_top_recommendations(self) -> List[str]:
        """Get top recommendations for the containerization plan"""
        recommendations = []

        for app in self.applications:
            scaling = self.scaling_recommendations.get(app.name)
            if scaling:
                recommendations.extend(scaling.warnings)

        # Add general recommendations
        stateful_count = sum(1 for app in self.applications if app.is_stateful)
        if stateful_count > 0:
            recommendations.append(
                f"Consider using managed services for {stateful_count} stateful application(s) in production"
            )

        high_cpu_apps = [app.name for app in self.applications if app.cpu_avg > 50]
        if high_cpu_apps:
            recommendations.append(
                f"High CPU usage detected in {', '.join(high_cpu_apps)} - ensure adequate autoscaling"
            )

        return recommendations[:5]  # Top 5 recommendations

    def _dict_to_yaml(self, data: Dict, indent: int = 0) -> str:
        """Convert dictionary to YAML string"""
        lines = []
        indent_str = '  ' * indent

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{indent_str}{key}:")
                lines.append(self._dict_to_yaml(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{indent_str}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for k, v in item.items():
                            prefix = '- ' if first else '  '
                            first = False
                            if isinstance(v, dict):
                                lines.append(f"{indent_str}  {prefix}{k}:")
                                lines.append(self._dict_to_yaml(v, indent + 3))
                            elif isinstance(v, list):
                                lines.append(f"{indent_str}  {prefix}{k}:")
                                for sub_item in v:
                                    lines.append(f"{indent_str}      - {sub_item}")
                            else:
                                lines.append(f"{indent_str}  {prefix}{k}: {self._yaml_value(v)}")
                    else:
                        lines.append(f"{indent_str}  - {self._yaml_value(item)}")
            else:
                lines.append(f"{indent_str}{key}: {self._yaml_value(value)}")

        return '\n'.join(lines)

    def _yaml_value(self, value: Any) -> str:
        """Format a value for YAML"""
        if value is None:
            return 'null'
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, str):
            if any(c in value for c in ':{}[]&*#?|-<>=!%@`'):
                return f'"{value}"'
            return value
        else:
            return str(value)

    @staticmethod
    def _profile_to_dict(profile: ApplicationProfile) -> Dict:
        """Convert ApplicationProfile to dictionary"""
        return {
            'name': profile.name,
            'app_type': profile.app_type,
            'processes': profile.processes,
            'ports': profile.ports,
            'cpu_avg': round(profile.cpu_avg, 1),
            'cpu_max': round(profile.cpu_max, 1),
            'memory_avg_mb': round(profile.memory_avg_mb, 0),
            'memory_max_mb': round(profile.memory_max_mb, 0),
            'network_in_mbps': round(profile.network_in_mbps, 2),
            'network_out_mbps': round(profile.network_out_mbps, 2),
            'is_stateful': profile.is_stateful,
            'scaling_profile': profile.scaling_profile,
            'resources': profile.metadata.get('resources', {})
        }

    @staticmethod
    def _recommendation_to_dict(rec: ScalingRecommendation) -> Dict:
        """Convert ScalingRecommendation to dictionary"""
        return {
            'strategy': rec.strategy,
            'min_replicas': rec.min_replicas,
            'max_replicas': rec.max_replicas,
            'target_cpu_percent': rec.target_cpu_percent,
            'target_memory_percent': rec.target_memory_percent,
            'cooldown_seconds': rec.cooldown_seconds,
            'reasoning': rec.reasoning,
            'warnings': rec.warnings
        }
