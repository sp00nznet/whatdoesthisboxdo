# Datadog Integration Guide

Analyze servers using Datadog metrics without SSH/WinRM access. This integration pulls historical data from the Datadog API, applies the same heuristics used in direct server analysis, and builds a learning database of patterns over time.

## Overview

The Datadog integration provides:

- **Metrics Analysis** - CPU, memory, disk, network, and load analysis
- **Process Detection** - Identify running applications from Datadog process data
- **Pattern Learning** - Build a database of known patterns across your infrastructure
- **Baseline Detection** - Store normal behavior for anomaly detection
- **Insight Tracking** - Track issues and their resolution over time
- **Monitor Integration** - Check active alerts and warnings

## Configuration

### Environment Variables

```bash
# Required
DATADOG_API_KEY=your_api_key_here
DATADOG_APP_KEY=your_application_key_here

# Optional (defaults to US1)
DATADOG_SITE=datadoghq.com
```

### Datadog Sites

| Site | URL | Region |
|------|-----|--------|
| US1 | `datadoghq.com` | United States (default) |
| US3 | `us3.datadoghq.com` | United States |
| US5 | `us5.datadoghq.com` | United States |
| EU | `datadoghq.eu` | Europe |
| AP1 | `ap1.datadoghq.com` | Asia Pacific |

### Getting API Keys

1. Log into your Datadog account
2. Go to **Organization Settings** > **API Keys**
3. Create or copy an existing API key
4. Go to **Organization Settings** > **Application Keys**
5. Create a new Application key

**Required Permissions:**
- Read access to metrics
- Read access to hosts
- Read access to monitors (optional)
- Read access to events (optional)
- Read access to processes (optional)

## Web Interface

### Dashboard (`/datadog`)

The Datadog dashboard provides:

- **Quick Actions** - Analyze servers or manage credentials
- **Open Insights** - View unresolved issues across all hosts
- **Recent Analyses** - History of recent Datadog analyses
- **Learned Patterns** - Patterns discovered across your infrastructure

### Analyzing a Server (`/datadog/analyze`)

1. Enter the hostname as it appears in Datadog
2. Select a lookback period (1 hour to 7 days)
3. Choose saved credentials or enter API keys manually
4. Check "Save to database" to enable pattern learning
5. Click "Start Analysis"

### Viewing Insights (`/datadog/insights`)

Filter and manage insights:

- **Hostname** - Filter by specific server
- **Severity** - Critical, Warning, or Info
- **Status** - Open or Resolved

Click "Resolve" to mark an insight as addressed.

### Viewing Patterns (`/datadog/patterns`)

Patterns are automatically learned as you analyze more servers:

- **Spike** - Sudden increases in metric values
- **Trend** - Gradual increases or decreases over time
- **Variability** - High variance in metric values
- **Asymmetric Traffic** - Unbalanced network I/O

Patterns with high occurrence counts indicate common infrastructure behaviors.

### Analysis History (`/datadog/history`)

View all past analyses with:

- Health scores over time
- Detected server types
- Issue counts
- Pattern counts

## REST API

### Analyze a Server

```bash
POST /api/v1/datadog/analyze
Content-Type: application/json
X-API-Key: YOUR_API_KEY

{
  "hostname": "web-server-01.example.com",
  "lookback_hours": 24,
  "dd_credential_id": 1,
  "save_to_db": true
}
```

Or with inline credentials:

```bash
{
  "hostname": "web-server-01.example.com",
  "lookback_hours": 24,
  "api_key": "your_datadog_api_key",
  "app_key": "your_datadog_app_key",
  "site": "datadoghq.com",
  "save_to_db": true
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "job_id": "abc123",
    "status": "pending",
    "message": "Datadog analysis started"
  }
}
```

### Check Job Status

```bash
GET /api/v1/jobs/{job_id}
X-API-Key: YOUR_API_KEY
```

### Get Insights

```bash
GET /api/v1/datadog/insights?hostname=web-server-01&severity=critical&status=open
X-API-Key: YOUR_API_KEY
```

### Get Learned Patterns

```bash
GET /api/v1/datadog/patterns?type=spike&min_occurrences=3
X-API-Key: YOUR_API_KEY
```

### Get Analysis History

```bash
GET /api/v1/datadog/history?hostname=web-server-01&limit=10
X-API-Key: YOUR_API_KEY
```

### Get Baselines

```bash
GET /api/v1/datadog/baselines/{hostname}
X-API-Key: YOUR_API_KEY
```

### Manage Credentials

```bash
# List credentials
GET /api/v1/datadog/credentials
X-API-Key: YOUR_API_KEY

# Create credential
POST /api/v1/datadog/credentials
Content-Type: application/json
X-API-Key: YOUR_API_KEY

{
  "name": "Production",
  "api_key": "...",
  "app_key": "...",
  "site": "datadoghq.com",
  "description": "Production Datadog account"
}
```

## Analysis Details

### Metrics Collected

| Metric | Description | Datadog Query |
|--------|-------------|---------------|
| CPU | Total CPU usage | `system.cpu.user + system.cpu.system` |
| Memory | Memory utilization | `system.mem.used / system.mem.total` |
| Load | System load average | `system.load.1`, `system.load.5`, `system.load.15` |
| Disk | Disk space usage | `system.disk.in_use` |
| Disk I/O | Read/write operations | `system.io.r_s`, `system.io.w_s` |
| Network | Bytes in/out | `system.net.bytes_rcvd`, `system.net.bytes_sent` |
| Processes | Process count | `system.proc.count` |

### Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU Average | 70% | 90% |
| CPU Idle (waste) | < 10% | - |
| Memory | 80% | 90% |
| Memory (waste) | < 30% | - |
| Disk | 80% | 90% |
| Load (absolute) | > 4 | > 8 |

### Server Type Detection

The analyzer detects server types from running processes:

| Type | Processes |
|------|-----------|
| Web Server | nginx, apache, httpd, caddy |
| App Server | gunicorn, uwsgi, uvicorn, node, java |
| Database | mysql, postgres, mongodb, redis |
| Container Host | docker, containerd, podman |
| Kubernetes | kubelet, kube-proxy, etcd |
| Message Queue | rabbitmq, kafka, activemq |
| Cache | redis, memcached, varnish |
| Monitoring | prometheus, grafana, datadog |
| CI/CD | jenkins, gitlab-runner, drone |
| Worker | celery, sidekiq, resque |

## Database Schema

### Tables

**datadog_credentials** - Encrypted API credentials storage

| Column | Type | Description |
|--------|------|-------------|
| id | int | Primary key |
| name | string | Credential name |
| api_key_encrypted | text | Encrypted API key |
| app_key_encrypted | text | Encrypted App key |
| site | string | Datadog site URL |
| description | text | Optional description |

**datadog_patterns** - Learned patterns database

| Column | Type | Description |
|--------|------|-------------|
| pattern_hash | string | Unique pattern identifier |
| pattern_type | string | spike, trend, variability, etc. |
| description | text | Human-readable description |
| metrics_involved | json | List of metric names |
| occurrence_count | int | Times this pattern seen |
| first_seen | timestamp | First detection time |
| last_seen | timestamp | Most recent detection |
| confidence | float | 0.0 to 1.0 confidence score |

**datadog_insights** - Tracked insights

| Column | Type | Description |
|--------|------|-------------|
| hostname | string | Server hostname |
| category | string | performance, capacity, anomaly |
| severity | string | critical, warning, info |
| title | string | Insight title |
| resolution_status | string | open, resolved |
| suggested_action | text | Recommended action |

**datadog_baselines** - Normal behavior baselines

| Column | Type | Description |
|--------|------|-------------|
| hostname | string | Server hostname |
| metric_name | string | Metric being baselined |
| baseline_avg | float | Average value |
| baseline_min | float | Minimum value |
| baseline_max | float | Maximum value |
| baseline_stddev | float | Standard deviation |

**datadog_analysis_history** - Full analysis records

| Column | Type | Description |
|--------|------|-------------|
| hostname | string | Server hostname |
| health_score | int | 0-100 health score |
| server_types | json | Detected server types |
| critical_count | int | Critical issues found |
| warning_count | int | Warnings found |
| analysis_data | json | Full analysis results |

## Pattern Learning

The system learns patterns automatically:

1. **First Analysis** - Patterns detected are marked as "novel"
2. **Subsequent Analyses** - If the same pattern is seen again, occurrence count increases
3. **High Occurrence** - Patterns seen 5+ times are considered "common"
4. **Cross-Host Learning** - Patterns from all hosts contribute to the knowledge base

### Using Patterns

Patterns help identify:

- **Expected Behavior** - Common patterns are likely normal
- **Anomalies** - Novel patterns on a server with established baselines may indicate issues
- **Infrastructure-Wide Issues** - Same pattern appearing across multiple hosts

## Programmatic Usage

### Python

```python
from connectors.datadog_connector import DatadogConnector, DatadogConfig
from analyzers.datadog_analyzer import DatadogAnalyzer

# Create connector
config = DatadogConfig(
    api_key='your_api_key',
    app_key='your_app_key',
    site='datadoghq.com'
)
connector = DatadogConnector(config)

# Test connection
if connector.test_connection():
    # Fetch data
    data = connector.get_all_data_for_host('web-server-01', lookback_hours=24)

    # Analyze
    analyzer = DatadogAnalyzer()
    results = analyzer.analyze(data)

    print(f"Health Score: {results['health_score']}")
    print(f"Server Types: {results['server_types']}")
    for insight in results['insights']:
        print(f"  [{insight['severity']}] {insight['title']}")
```

### Using the Analyzer Class

```python
from analyzer import ServerAnalyzer

analyzer = ServerAnalyzer()

# Run Datadog-only analysis (no SSH)
results = analyzer.run_datadog_only_analysis(
    hostname='web-server-01',
    lookback_hours=24
)

print(results['summary'])
```

## Troubleshooting

### "Failed to connect to Datadog API"

1. Verify API key and App key are correct
2. Check the site URL matches your Datadog account region
3. Ensure network access to Datadog API endpoints
4. Verify API key has required permissions

### "No data found for host"

1. Verify the hostname matches exactly (case-sensitive)
2. Check that the Datadog agent is installed and reporting
3. Try searching for the host in Datadog UI first
4. Extend the lookback period

### "Datadog connector not available"

The `requests` library is required:

```bash
pip install requests
```

## Best Practices

1. **Use Saved Credentials** - More secure than inline API keys
2. **24-Hour Lookback** - Good balance of data and performance
3. **Enable Database Storage** - Enables pattern learning
4. **Regular Analysis** - Run weekly to track trends
5. **Resolve Insights** - Keep the insight list manageable
