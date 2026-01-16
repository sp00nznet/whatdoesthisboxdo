# Containerization Planner Guide

Generate production-ready Docker and Kubernetes configurations based on actual server metrics from Datadog. The planner identifies applications, profiles resource usage, and creates optimized container configurations with scaling strategies.

## Overview

The Containerization Planner:

1. **Identifies Applications** - Detects running apps from process signatures
2. **Profiles Resources** - Calculates CPU/memory needs from metrics
3. **Recommends Scaling** - Horizontal vs vertical based on workload
4. **Generates Configurations** - Dockerfiles, docker-compose, Kubernetes

## Quick Start

### Web Interface

1. Navigate to `/datadog/containerize`
2. Enter the hostname as it appears in Datadog
3. Select lookback period (24 hours recommended)
4. Choose credentials
5. Click "Generate Containerization Plan"

### API

```bash
curl -X POST http://localhost:5000/api/v1/datadog/containerize \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "web-server-01.example.com",
    "lookback_hours": 24,
    "dd_credential_id": 1
  }'
```

## Application Detection

### Supported Applications

The planner recognizes 15+ application types:

| Category | Applications | Base Image |
|----------|--------------|------------|
| **Web Servers** | nginx, Apache, Caddy | `nginx:alpine`, `httpd:alpine` |
| **App Servers** | Node.js, Python/Gunicorn, Java/Spring | `node:20-alpine`, `python:3.11-slim`, `eclipse-temurin:21-jre` |
| **Databases** | PostgreSQL, MySQL, MongoDB | `postgres:16-alpine`, `mysql:8`, `mongo:7` |
| **Caches** | Redis, Memcached | `redis:7-alpine`, `memcached:alpine` |
| **Queues** | RabbitMQ, Kafka | `rabbitmq:3-management-alpine`, `confluentinc/cp-kafka` |
| **Search** | Elasticsearch | `elasticsearch:8.11.0` |
| **Workers** | Celery, Sidekiq | `python:3.11-slim`, `ruby:3.2-alpine` |

### Detection Logic

Applications are detected by matching running processes:

```python
# Example: Node.js detection
processes: ['node', 'npm', 'yarn']
ports: [3000, 8080, 5000]
base_image: 'node:20-alpine'
scaling: 'horizontal'
```

## Resource Calculation

### CPU Sizing

```
CPU Request = (Average CPU % / 100) × Total Cores × 1000m × 1.3 headroom
CPU Limit = (Max CPU % / 100) × Total Cores × 1000m × 1.3 headroom
```

Values are rounded to "nice numbers": 100m, 250m, 500m, 1000m, 2000m, 4000m

### Memory Sizing

```
Memory Request = Average Memory MB × 1.3 headroom
Memory Limit = Max Memory MB × 1.3 headroom
```

Values are rounded to: 128Mi, 256Mi, 512Mi, 1Gi, 2Gi, 4Gi, 8Gi

### Example Calculation

Server metrics:
- CPU: 35% avg, 72% max (4 cores)
- Memory: 1.5GB avg, 2.8GB max

Calculated resources:
- CPU Request: 500m (35% × 4000m × 1.3 = 1820m, rounded to nice number)
- CPU Limit: 1000m (72% × 4000m × 1.3 = 3744m, rounded)
- Memory Request: 2Gi (1500MB × 1.3 = 1950MB, rounded to 2048Mi)
- Memory Limit: 4Gi (2800MB × 1.3 = 3640MB, rounded to 4096Mi)

## Scaling Recommendations

### Strategy Selection

| Condition | Strategy | Reasoning |
|-----------|----------|-----------|
| Stateful database | Vertical | Data consistency |
| High avg CPU (>60%) | Horizontal | Distribute load |
| Moderate load | Horizontal (2 replicas) | Redundancy |
| Low utilization | Single replica | Cost efficiency |
| CPU spikes (>80% max) | More max replicas | Handle bursts |

### Horizontal Scaling Parameters

```yaml
minReplicas: Based on average load
maxReplicas: Based on peak load
targetCPU: 70%
targetMemory: 75%
scaleUpCooldown: 60s
scaleDownCooldown: 300s
```

### Vertical Scaling Parameters

```yaml
minReplicas: 1
maxReplicas: 1-3 (for failover)
targetCPU: 80%
targetMemory: 85%
cooldown: 600s
```

## Generated Configurations

### Dockerfiles

Each detected application gets a customized Dockerfile:

**Node.js Example:**

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (for layer caching)
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY . .

# Build if needed
RUN npm run build --if-present

# Run as non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["node", "server.js"]
```

**PostgreSQL Example:**

```dockerfile
FROM postgres:16-alpine

# PostgreSQL customizations
COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY init-scripts/ /docker-entrypoint-initdb.d/

# Performance tuning based on metrics
# Recommended shared_buffers: 512MB
# Recommended effective_cache_size: 1536MB
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  nodejs:
    build:
      context: ./nodejs
      dockerfile: Dockerfile
    image: nodejs:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    environment:
      NODE_ENV: production
      LOG_LEVEL: info
    networks:
      - app-network

  postgresql:
    build:
      context: ./postgresql
      dockerfile: Dockerfile
    image: postgresql:latest
    restart: unless-stopped
    ports:
      - "5432:5432"
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2048M
        reservations:
          cpus: '0.50'
          memory: 1024M
    volumes:
      - postgresql-data:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-app}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-app}
    networks:
      - app-network

networks:
  app-network:
    driver: bridge

volumes:
  postgresql-data:
    driver: local
```

### Kubernetes Manifests

**Deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nodejs
  labels:
    app: nodejs
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nodejs
  template:
    metadata:
      labels:
        app: nodejs
    spec:
      containers:
        - name: nodejs
          image: nodejs:latest
          imagePullPolicy: Always
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 512Mi
          ports:
            - containerPort: 3000
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - nodejs
                topologyKey: kubernetes.io/hostname
```

**Service:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nodejs
spec:
  selector:
    app: nodejs
  ports:
    - port: 3000
      targetPort: 3000
  type: ClusterIP
```

**HorizontalPodAutoscaler:**

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: nodejs-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nodejs
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 75
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

**PersistentVolumeClaim (for stateful apps):**

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgresql-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 10Gi
```

## Output Structure

```
containerization-{hostname}-{timestamp}/
├── dockerfiles/
│   ├── Dockerfile.nodejs
│   ├── Dockerfile.postgresql
│   └── Dockerfile.redis
├── docker-compose.yml
├── kubernetes/
│   ├── namespace.yaml
│   ├── nodejs-deployment.yaml
│   ├── nodejs-service.yaml
│   ├── nodejs-hpa.yaml
│   ├── postgresql-deployment.yaml
│   ├── postgresql-service.yaml
│   ├── postgresql-pvc.yaml
│   └── ...
└── plan.json
```

## API Reference

### Generate Plan

```bash
POST /api/v1/datadog/containerize
Content-Type: application/json
X-API-Key: YOUR_KEY

{
  "hostname": "web-server-01",
  "lookback_hours": 24,
  "dd_credential_id": 1
}
```

**Response (Job Created):**

```json
{
  "success": true,
  "data": {
    "job_id": "abc123",
    "status": "pending",
    "message": "Containerization planning started"
  }
}
```

### Check Job Status

```bash
GET /api/v1/jobs/{job_id}
X-API-Key: YOUR_KEY
```

**Response (Completed):**

```json
{
  "success": true,
  "data": {
    "status": "completed",
    "result": {
      "hostname": "web-server-01",
      "output_dir": "output/containerization-web-server-01-20240115-120000",
      "plan": {
        "applications": [...],
        "scaling_recommendations": {...},
        "configurations": {...},
        "summary": {...}
      }
    }
  }
}
```

## Programmatic Usage

```python
from connectors.datadog_connector import DatadogConnector, DatadogConfig
from analyzers.datadog_analyzer import DatadogAnalyzer
from generators.containerization_planner import ContainerizationPlanner

# Fetch Datadog data
config = DatadogConfig(api_key='...', app_key='...', site='datadoghq.com')
connector = DatadogConnector(config)
datadog_data = connector.get_all_data_for_host('web-server-01', lookback_hours=24)

# Run analysis
analyzer = DatadogAnalyzer()
analysis_results = analyzer.analyze(datadog_data)

# Generate containerization plan
planner = ContainerizationPlanner(datadog_data, analysis_results)
plan = planner.analyze_and_plan()

# Access results
print(f"Detected {len(plan['applications'])} applications")
for app in plan['applications']:
    print(f"  - {app['name']} ({app['app_type']})")
    print(f"    CPU: {app['resources']['cpu_request_millicores']}m request")
    print(f"    Memory: {app['resources']['memory_request_mb']}Mi request")

# Get docker-compose
print(plan['configurations']['docker_compose'])

# Get Kubernetes manifests
for filename, content in plan['configurations']['kubernetes'].items():
    print(f"\n--- {filename} ---")
    print(content)
```

## Best Practices

### Before Using Generated Configs

1. **Review Resource Limits** - Adjust based on your specific workload
2. **Update Health Check Endpoints** - Change `/health` to your actual endpoint
3. **Add Environment Variables** - Add app-specific configuration
4. **Configure Secrets** - Use Kubernetes Secrets or docker-compose secrets
5. **Adjust Storage** - Modify PVC sizes for your data needs

### Production Considerations

1. **Use Managed Services** for databases when possible
2. **Enable Pod Disruption Budgets** for high availability
3. **Configure Network Policies** for security
4. **Set up monitoring** (Prometheus, Datadog)
5. **Implement proper logging** (stdout/stderr to log aggregator)

### Scaling Tips

1. **Start Conservative** - Begin with recommended min replicas
2. **Monitor Actual Usage** - Adjust after observing real traffic
3. **Test Scaling** - Verify HPA triggers correctly
4. **Consider Time-Based Scaling** - For predictable traffic patterns

## Limitations

1. **Process Detection** - Relies on Datadog process monitoring being enabled
2. **Generic Templates** - Dockerfiles may need customization
3. **No Application Code** - Copies must be done manually
4. **Database Migrations** - Not included in generated configs
5. **External Dependencies** - May need additional services (S3, etc.)

## Troubleshooting

### "No applications detected"

- Ensure Datadog process monitoring is enabled
- Check that the agent is reporting process data
- Verify hostname matches exactly

### "Resources seem too high/low"

- Extend lookback period for better averages
- Check for anomalies during the analysis period
- Manually adjust resource values in generated files

### "Missing application type"

The planner uses conservative defaults for unrecognized apps:

```yaml
base_image: ubuntu:22.04
scaling: horizontal
```

Customize the Dockerfile for your specific application.
