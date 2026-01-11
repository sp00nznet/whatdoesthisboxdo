"""
Metrics Monitor
Collects system metrics over a configurable time period for better analysis
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from connectors.ssh_executor import SSHExecutor

logger = logging.getLogger(__name__)


@dataclass
class MetricsSample:
    """A single metrics sample"""
    timestamp: datetime
    cpu_percent: float
    load_avg: List[float]
    memory_percent: float
    memory_used_mb: int
    disk_io_read: int = 0
    disk_io_write: int = 0
    net_bytes_sent: int = 0
    net_bytes_recv: int = 0
    processes_count: int = 0
    top_cpu_processes: List[Dict] = field(default_factory=list)
    top_mem_processes: List[Dict] = field(default_factory=list)


class MetricsMonitor:
    """Monitors system metrics over time via SSH"""

    def __init__(self, ssh: SSHExecutor):
        self.ssh = ssh
        self.samples: List[MetricsSample] = []
        self.monitoring = False

    def collect_sample(self) -> MetricsSample:
        """Collect a single metrics sample"""
        timestamp = datetime.now()

        # CPU usage via top (1 iteration)
        cpu_percent = 0.0
        exit_code, stdout, _ = self.ssh.execute(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'",
            use_sudo=False
        )
        if exit_code == 0 and stdout.strip():
            try:
                cpu_percent = float(stdout.strip().replace(',', '.'))
            except ValueError:
                pass

        # Load average
        load_avg = [0.0, 0.0, 0.0]
        exit_code, stdout, _ = self.ssh.execute("cat /proc/loadavg", use_sudo=False)
        if exit_code == 0:
            parts = stdout.strip().split()
            load_avg = [float(x) for x in parts[:3]]

        # Memory
        memory_percent = 0.0
        memory_used_mb = 0
        exit_code, stdout, _ = self.ssh.execute("free -m", use_sudo=False)
        if exit_code == 0:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    memory_used_mb = used
                    memory_percent = round(used / total * 100, 1) if total > 0 else 0

        # Disk I/O
        disk_io_read = 0
        disk_io_write = 0
        exit_code, stdout, _ = self.ssh.execute(
            "cat /proc/diskstats | awk '{read+=$6; write+=$10} END {print read, write}'",
            use_sudo=False
        )
        if exit_code == 0:
            parts = stdout.strip().split()
            if len(parts) >= 2:
                disk_io_read = int(parts[0]) * 512  # sectors to bytes
                disk_io_write = int(parts[1]) * 512

        # Network I/O
        net_bytes_sent = 0
        net_bytes_recv = 0
        exit_code, stdout, _ = self.ssh.execute(
            "cat /proc/net/dev | tail -n +3 | awk '{rx+=$2; tx+=$10} END {print rx, tx}'",
            use_sudo=False
        )
        if exit_code == 0:
            parts = stdout.strip().split()
            if len(parts) >= 2:
                net_bytes_recv = int(parts[0])
                net_bytes_sent = int(parts[1])

        # Process count
        processes_count = 0
        exit_code, stdout, _ = self.ssh.execute("ps aux --no-headers | wc -l", use_sudo=False)
        if exit_code == 0:
            processes_count = int(stdout.strip())

        # Top CPU processes
        top_cpu_processes = []
        exit_code, stdout, _ = self.ssh.execute(
            "ps aux --sort=-%cpu --no-headers | head -5",
            use_sudo=True
        )
        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        top_cpu_processes.append({
                            'name': parts[10].split()[0],
                            'cpu': float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                            'mem': float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            'user': parts[0]
                        })

        # Top memory processes
        top_mem_processes = []
        exit_code, stdout, _ = self.ssh.execute(
            "ps aux --sort=-%mem --no-headers | head -5",
            use_sudo=True
        )
        if exit_code == 0:
            for line in stdout.strip().split('\n'):
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        top_mem_processes.append({
                            'name': parts[10].split()[0],
                            'cpu': float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                            'mem': float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            'user': parts[0]
                        })

        sample = MetricsSample(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            load_avg=load_avg,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            disk_io_read=disk_io_read,
            disk_io_write=disk_io_write,
            net_bytes_sent=net_bytes_sent,
            net_bytes_recv=net_bytes_recv,
            processes_count=processes_count,
            top_cpu_processes=top_cpu_processes,
            top_mem_processes=top_mem_processes
        )

        self.samples.append(sample)
        return sample

    def monitor(self, duration_seconds: int, interval_seconds: int = 5) -> List[MetricsSample]:
        """
        Monitor system metrics for a specified duration.

        Args:
            duration_seconds: How long to monitor (in seconds)
            interval_seconds: Time between samples (in seconds)

        Returns:
            List of collected samples
        """
        self.samples = []
        self.monitoring = True
        start_time = time.time()
        sample_count = 0

        logger.info(f"Starting metrics collection for {duration_seconds}s (interval: {interval_seconds}s)")
        print(f"\n  Collecting metrics for {duration_seconds} seconds...")

        while self.monitoring and (time.time() - start_time) < duration_seconds:
            sample = self.collect_sample()
            sample_count += 1
            elapsed = int(time.time() - start_time)
            remaining = duration_seconds - elapsed

            # Progress indicator
            print(f"\r  [{elapsed}s/{duration_seconds}s] CPU: {sample.cpu_percent:.1f}% | "
                  f"MEM: {sample.memory_percent:.1f}% | "
                  f"Load: {sample.load_avg[0]:.2f} | "
                  f"Samples: {sample_count}", end='', flush=True)

            if remaining > interval_seconds:
                time.sleep(interval_seconds)

        print(f"\n  Collected {len(self.samples)} samples\n")
        logger.info(f"Metrics collection complete: {len(self.samples)} samples")

        return self.samples

    def stop(self):
        """Stop monitoring"""
        self.monitoring = False

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics from collected samples"""
        if not self.samples:
            return {}

        cpu_values = [s.cpu_percent for s in self.samples]
        mem_values = [s.memory_percent for s in self.samples]
        load_values = [s.load_avg[0] for s in self.samples]

        # Calculate I/O rates (bytes per second)
        io_rates = {'disk_read': [], 'disk_write': [], 'net_recv': [], 'net_sent': []}
        for i in range(1, len(self.samples)):
            time_diff = (self.samples[i].timestamp - self.samples[i-1].timestamp).total_seconds()
            if time_diff > 0:
                io_rates['disk_read'].append(
                    (self.samples[i].disk_io_read - self.samples[i-1].disk_io_read) / time_diff
                )
                io_rates['disk_write'].append(
                    (self.samples[i].disk_io_write - self.samples[i-1].disk_io_write) / time_diff
                )
                io_rates['net_recv'].append(
                    (self.samples[i].net_bytes_recv - self.samples[i-1].net_bytes_recv) / time_diff
                )
                io_rates['net_sent'].append(
                    (self.samples[i].net_bytes_sent - self.samples[i-1].net_bytes_sent) / time_diff
                )

        # Find processes that appear most frequently in top lists
        cpu_process_counts = {}
        mem_process_counts = {}
        for sample in self.samples:
            for proc in sample.top_cpu_processes:
                name = proc['name']
                cpu_process_counts[name] = cpu_process_counts.get(name, 0) + 1
            for proc in sample.top_mem_processes:
                name = proc['name']
                mem_process_counts[name] = mem_process_counts.get(name, 0) + 1

        return {
            'duration_seconds': (self.samples[-1].timestamp - self.samples[0].timestamp).total_seconds() if len(self.samples) > 1 else 0,
            'sample_count': len(self.samples),
            'cpu': {
                'min': min(cpu_values),
                'max': max(cpu_values),
                'avg': sum(cpu_values) / len(cpu_values),
                'samples': cpu_values
            },
            'memory': {
                'min': min(mem_values),
                'max': max(mem_values),
                'avg': sum(mem_values) / len(mem_values),
                'samples': mem_values
            },
            'load': {
                'min': min(load_values),
                'max': max(load_values),
                'avg': sum(load_values) / len(load_values),
                'samples': load_values
            },
            'io_rates': {
                'disk_read_avg': sum(io_rates['disk_read']) / len(io_rates['disk_read']) if io_rates['disk_read'] else 0,
                'disk_write_avg': sum(io_rates['disk_write']) / len(io_rates['disk_write']) if io_rates['disk_write'] else 0,
                'net_recv_avg': sum(io_rates['net_recv']) / len(io_rates['net_recv']) if io_rates['net_recv'] else 0,
                'net_sent_avg': sum(io_rates['net_sent']) / len(io_rates['net_sent']) if io_rates['net_sent'] else 0,
            },
            'top_cpu_processes': sorted(cpu_process_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_mem_processes': sorted(mem_process_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            'process_count_avg': sum(s.processes_count for s in self.samples) / len(self.samples)
        }

    def get_analysis(self) -> Dict[str, Any]:
        """
        Analyze collected metrics and provide opinions/recommendations.
        Returns insights about system health and usage patterns.
        """
        summary = self.get_summary()
        if not summary:
            return {'status': 'no_data', 'insights': []}

        insights = []
        warnings = []
        recommendations = []
        health_score = 100  # Start at 100, deduct for issues

        # CPU Analysis
        cpu_avg = summary['cpu']['avg']
        cpu_max = summary['cpu']['max']

        if cpu_avg > 80:
            health_score -= 25
            warnings.append("CPU usage is critically high")
            recommendations.append("Consider scaling up CPU resources or optimizing CPU-intensive processes")
        elif cpu_avg > 60:
            health_score -= 10
            warnings.append("CPU usage is elevated")
            insights.append(f"System is under moderate CPU load (avg: {cpu_avg:.1f}%)")
        elif cpu_avg < 10:
            insights.append("CPU is underutilized - this server may be overprovisioned")
            recommendations.append("Consider downsizing to a smaller instance to reduce costs")
        else:
            insights.append(f"CPU usage is healthy (avg: {cpu_avg:.1f}%)")

        if cpu_max > 95:
            warnings.append(f"CPU spiked to {cpu_max:.1f}% during monitoring - possible performance bottleneck")

        # Memory Analysis
        mem_avg = summary['memory']['avg']
        mem_max = summary['memory']['max']

        if mem_avg > 85:
            health_score -= 25
            warnings.append("Memory usage is critically high - risk of OOM")
            recommendations.append("Add more RAM or identify memory leaks")
        elif mem_avg > 70:
            health_score -= 10
            warnings.append("Memory usage is elevated")
            insights.append(f"System is using significant memory (avg: {mem_avg:.1f}%)")
        elif mem_avg < 20:
            insights.append("Memory is underutilized - server may be overprovisioned")
            recommendations.append("Consider downsizing to a smaller instance")
        else:
            insights.append(f"Memory usage is healthy (avg: {mem_avg:.1f}%)")

        # Load Analysis
        # Compare load to number of CPUs would be ideal, but we estimate
        load_avg = summary['load']['avg']
        load_max = summary['load']['max']

        if load_avg > 4:
            health_score -= 15
            warnings.append(f"System load is very high (avg: {load_avg:.2f})")
            recommendations.append("Investigate processes causing high load")
        elif load_avg > 2:
            insights.append(f"System load is moderate (avg: {load_avg:.2f})")
        else:
            insights.append(f"System load is low (avg: {load_avg:.2f})")

        # I/O Analysis
        disk_read = summary['io_rates']['disk_read_avg']
        disk_write = summary['io_rates']['disk_write_avg']
        net_recv = summary['io_rates']['net_recv_avg']
        net_sent = summary['io_rates']['net_sent_avg']

        # Disk I/O (rough thresholds)
        if disk_read > 100_000_000 or disk_write > 100_000_000:  # 100MB/s
            warnings.append("High disk I/O detected - possible storage bottleneck")
            recommendations.append("Consider using faster storage (SSD/NVMe) or optimizing I/O patterns")
        elif disk_read > 10_000_000 or disk_write > 10_000_000:  # 10MB/s
            insights.append("Moderate disk I/O activity detected")

        # Network I/O
        if net_recv > 100_000_000 or net_sent > 100_000_000:  # 100MB/s
            insights.append("High network throughput - this is a network-intensive workload")
        elif net_recv > 10_000_000 or net_sent > 10_000_000:  # 10MB/s
            insights.append("Moderate network activity detected")

        # Process Analysis
        top_cpu = summary.get('top_cpu_processes', [])
        top_mem = summary.get('top_mem_processes', [])

        if top_cpu:
            top_cpu_name = top_cpu[0][0]
            insights.append(f"Primary CPU consumer: {top_cpu_name}")

        if top_mem:
            top_mem_name = top_mem[0][0]
            insights.append(f"Primary memory consumer: {top_mem_name}")

        # Variability analysis
        cpu_variance = max(summary['cpu']['samples']) - min(summary['cpu']['samples'])
        if cpu_variance > 50:
            insights.append("CPU usage is highly variable - workload is bursty")

        mem_variance = max(summary['memory']['samples']) - min(summary['memory']['samples'])
        if mem_variance > 20:
            insights.append("Memory usage fluctuates significantly")

        # Overall assessment
        if health_score >= 90:
            overall = "excellent"
            assessment = "System is healthy and performing well"
        elif health_score >= 70:
            overall = "good"
            assessment = "System is generally healthy with some areas to watch"
        elif health_score >= 50:
            overall = "fair"
            assessment = "System has performance concerns that should be addressed"
        else:
            overall = "poor"
            assessment = "System has significant performance issues requiring immediate attention"

        return {
            'health_score': health_score,
            'overall_status': overall,
            'assessment': assessment,
            'insights': insights,
            'warnings': warnings,
            'recommendations': recommendations,
            'metrics_summary': {
                'cpu_avg': round(cpu_avg, 1),
                'cpu_max': round(cpu_max, 1),
                'memory_avg': round(mem_avg, 1),
                'memory_max': round(mem_max, 1),
                'load_avg': round(load_avg, 2),
                'disk_read_mb_s': round(disk_read / 1_000_000, 2),
                'disk_write_mb_s': round(disk_write / 1_000_000, 2),
                'net_recv_mb_s': round(net_recv / 1_000_000, 2),
                'net_sent_mb_s': round(net_sent / 1_000_000, 2),
            }
        }
