# REST API v1 Reference

The WhatDoesThisBoxDo web interface includes a REST API for programmatic access to server analysis and Infrastructure-as-Code generation.

## Authentication

All API endpoints require an API key passed via the `X-API-Key` header or `api_key` query parameter.

```bash
# Set API key in environment
export API_KEY="your-secure-api-key"

# Use via header (recommended)
curl -H "X-API-Key: $API_KEY" http://localhost:5000/api/v1/jobs

# Or via query parameter
curl http://localhost:5000/api/v1/jobs?api_key=$API_KEY
```

## Response Format

All API responses follow a consistent format:

```json
{
  "success": true,
  "data": { ... }
}
```

Error responses:

```json
{
  "success": false,
  "error": "Error message description"
}
```

---

## Analysis Endpoints

### Start Single Server Analysis

Start analysis of a single server.

```
POST /api/v1/analyze
```

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `hostname` | string | Yes* | - | Server hostname or IP address |
| `username` | string | Yes* | - | SSH/WinRM username |
| `password` | string | No* | - | SSH/WinRM password |
| `ssh_key` | string | No* | - | SSH private key content |
| `port` | integer | No | 22 | SSH port (or 5985 for WinRM) |
| `os_type` | string | No | `linux` | `linux` or `windows` |
| `credential_id` | integer | No | - | Use saved credential instead of manual auth |
| `monitor_duration` | integer | No | 0 | Metrics collection duration in seconds (0 = disabled) |
| `generate_ansible` | boolean | No | true | Generate basic Ansible playbooks |
| `generate_ansible_full` | boolean | No | true | Generate full system recreation playbooks |
| `generate_terraform` | boolean | No | true | Generate vSphere Terraform configuration |
| `generate_cloud` | boolean | No | true | Generate AWS, GCP, Azure Terraform configs |

*Either `credential_id` OR (`username` AND (`password` OR `ssh_key`)) is required.

**Example Request:**

```bash
curl -X POST http://localhost:5000/api/v1/analyze \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "server.example.com",
    "username": "ubuntu",
    "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
    "monitor_duration": 60,
    "generate_ansible": true,
    "generate_ansible_full": true,
    "generate_terraform": true,
    "generate_cloud": true
  }'
```

**Example Response:**

```json
{
  "success": true,
  "data": {
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "pending",
    "message": "Analysis started"
  }
}
```

---

### Start Batch Analysis

Analyze multiple servers at once.

```
POST /api/v1/batch
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `servers` | array | Yes | List of server objects (see below) |
| `credential_id` | integer | No | Apply this credential to all servers |
| `monitor_duration` | integer | No | Metrics duration for all servers (default: 0) |
| `generate_ansible` | boolean | No | Generate basic Ansible (default: true) |
| `generate_ansible_full` | boolean | No | Generate full Ansible (default: true) |
| `generate_terraform` | boolean | No | Generate vSphere Terraform (default: true) |
| `generate_cloud` | boolean | No | Generate cloud configs (default: true) |

**Server Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | Server hostname or IP |
| `username` | string | Yes* | SSH/WinRM username |
| `password` | string | No* | SSH/WinRM password |
| `ssh_key` | string | No* | SSH private key content |
| `port` | integer | No | SSH/WinRM port |
| `os_type` | string | No | `linux` or `windows` |

*Not required if using `credential_id` at the batch level.

**Example Request:**

```bash
curl -X POST http://localhost:5000/api/v1/batch \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "servers": [
      {"hostname": "web1.example.com"},
      {"hostname": "web2.example.com"},
      {"hostname": "db.example.com", "port": 2222}
    ],
    "credential_id": 1,
    "monitor_duration": 30,
    "generate_cloud": true
  }'
```

**Example Response:**

```json
{
  "success": true,
  "data": {
    "batch_id": "a1b2c3d4",
    "jobs": [
      {"job_id": "uuid-1", "hostname": "web1.example.com"},
      {"job_id": "uuid-2", "hostname": "web2.example.com"},
      {"job_id": "uuid-3", "hostname": "db.example.com"}
    ],
    "count": 3
  }
}
```

---

## Job Management Endpoints

### List Jobs

Get a list of all analysis jobs.

```
GET /api/v1/jobs
GET /api/v1/jobs?status=completed
GET /api/v1/jobs?batch_id=a1b2c3d4
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `status` | Filter by status: `pending`, `running`, `completed`, `failed` |
| `batch_id` | Filter by batch ID |

**Example Response:**

```json
{
  "success": true,
  "data": {
    "jobs": [
      {
        "job_id": "550e8400-e29b-41d4-a716-446655440000",
        "status": "completed",
        "hostname": "server.example.com",
        "batch_id": null,
        "created": "2024-01-15T10:30:00"
      }
    ],
    "count": 1
  }
}
```

---

### Get Job Status

Get detailed status of a specific job.

```
GET /api/v1/jobs/<job_id>
```

**Example Response (Completed):**

```json
{
  "success": true,
  "data": {
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "message": "Analysis complete!",
    "hostname": "server.example.com",
    "batch_id": null,
    "created": "2024-01-15T10:30:00",
    "error": null,
    "options": {
      "monitor_duration": 60,
      "generate_ansible": true,
      "generate_ansible_full": true,
      "generate_terraform": true,
      "generate_cloud": true
    },
    "files": {
      "markdown": "server_example_com_20240115_103000.md",
      "html": "server_example_com_20240115_103000.html",
      "json": "server_example_com_20240115_103000.json"
    },
    "output_dir": "server_example_com_20240115_103000",
    "generated_outputs": {
      "ansible": "ansible",
      "ansible_full": "ansible-full",
      "terraform_vsphere": "terraform-vsphere",
      "terraform_aws": "terraform-aws",
      "terraform_gcp": "terraform-gcp",
      "terraform_azure": "terraform-azure",
      "cost_estimate": "cost-estimate.json"
    },
    "download_urls": {
      "ansible": "/api/v1/outputs/server_example_com_20240115_103000/ansible",
      "ansible_full": "/api/v1/outputs/server_example_com_20240115_103000/ansible-full",
      "terraform_vsphere": "/api/v1/outputs/server_example_com_20240115_103000/terraform-vsphere",
      "terraform_aws": "/api/v1/outputs/server_example_com_20240115_103000/terraform-aws",
      "terraform_gcp": "/api/v1/outputs/server_example_com_20240115_103000/terraform-gcp",
      "terraform_azure": "/api/v1/outputs/server_example_com_20240115_103000/terraform-azure",
      "cost_estimate": "/api/v1/outputs/server_example_com_20240115_103000/cost_estimate"
    }
  }
}
```

---

### Get Job Result Data

Get the raw analysis result data.

```
GET /api/v1/jobs/<job_id>/result
GET /api/v1/jobs/<job_id>/result?format=json     # Default
GET /api/v1/jobs/<job_id>/result?format=markdown
GET /api/v1/jobs/<job_id>/result?format=html
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `format` | Output format: `json` (default), `markdown`, `html` |

---

### List Job Outputs

List available downloadable outputs for a completed job.

```
GET /api/v1/jobs/<job_id>/outputs
```

**Example Response:**

```json
{
  "success": true,
  "data": {
    "output_dir": "server_example_com_20240115_103000",
    "generated_outputs": {
      "ansible": "ansible",
      "ansible_full": "ansible-full",
      "terraform_aws": "terraform-aws",
      "terraform_gcp": "terraform-gcp",
      "terraform_azure": "terraform-azure"
    },
    "download_urls": {
      "ansible": "/api/v1/outputs/server_example_com_20240115_103000/ansible",
      "ansible_full": "/api/v1/outputs/server_example_com_20240115_103000/ansible-full"
    }
  }
}
```

---

### Download Job Output

Download a specific output from a completed job as a ZIP file.

```
GET /api/v1/jobs/<job_id>/outputs/<output_type>
```

**Available Output Types:**

| Type | Description |
|------|-------------|
| `ansible` | Basic Ansible playbooks |
| `ansible-full` | Full system recreation Ansible playbooks |
| `terraform-vsphere` | vSphere Terraform configuration |
| `terraform-aws` | AWS EC2 Terraform configuration |
| `terraform-gcp` | GCP Compute Engine Terraform configuration |
| `terraform-azure` | Azure VM Terraform configuration |
| `all-terraform` | All Terraform configs combined |
| `all` | All outputs combined (Ansible + Terraform + cost estimates) |

**Example:**

```bash
# Download full Ansible playbooks
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/jobs/<job_id>/outputs/ansible-full \
  -o ansible-full.zip

# Download all Terraform configs
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/jobs/<job_id>/outputs/all-terraform \
  -o terraform.zip

# Download everything
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/jobs/<job_id>/outputs/all \
  -o all-outputs.zip
```

---

## Output Endpoints

### List All Outputs

List all output directories with their available downloads.

```
GET /api/v1/outputs
```

**Example Response:**

```json
{
  "success": true,
  "data": {
    "outputs": [
      {
        "name": "server_example_com_20240115_103000",
        "available_outputs": {
          "ansible": true,
          "ansible-full": true,
          "terraform-vsphere": true,
          "terraform-aws": true,
          "terraform-gcp": true,
          "terraform-azure": true,
          "cost_estimate": true
        }
      }
    ],
    "count": 1
  }
}
```

---

### Download Output

Download a specific output as a ZIP file.

```
GET /api/v1/outputs/<output_dir>/<output_type>
```

**Example:**

```bash
# Download AWS Terraform
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/outputs/server_example_com_20240115_103000/terraform-aws \
  -o terraform-aws.zip
```

---

## Documentation Endpoints

### List Documentation Files

List all generated documentation files.

```
GET /api/v1/docs
```

**Example Response:**

```json
{
  "success": true,
  "data": {
    "documents": [
      {
        "name": "server_example_com_20240115_103000",
        "files": {
          "json": "server_example_com_20240115_103000.json",
          "markdown": "server_example_com_20240115_103000.md",
          "html": "server_example_com_20240115_103000.html"
        },
        "size": 45678,
        "created": "2024-01-15T10:35:00"
      }
    ],
    "count": 1
  }
}
```

---

### Download Documentation File

Download a specific documentation file.

```
GET /api/v1/docs/<filename>
```

**Example:**

```bash
# Download JSON analysis
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/docs/server_example_com_20240115_103000.json \
  -o analysis.json

# Download markdown documentation
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:5000/api/v1/docs/server_example_com_20240115_103000.md \
  -o documentation.md
```

---

## Credential Management Endpoints

### List Credentials

List all saved credentials (without sensitive data).

```
GET /api/v1/credentials
```

---

### Create Credential

Save a new credential for reuse.

```
POST /api/v1/credentials
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Credential name |
| `username` | string | Yes | SSH/WinRM username |
| `password` | string | No | SSH/WinRM password |
| `ssh_key` | string | No | SSH private key content |
| `hostname` | string | No | Default hostname |
| `port` | integer | No | Default port |
| `os_type` | string | No | `linux` or `windows` |
| `description` | string | No | Description |

---

### Get/Update/Delete Credential

```
GET    /api/v1/credentials/<id>
PUT    /api/v1/credentials/<id>
DELETE /api/v1/credentials/<id>
```

---

## Complete Workflow Example

Here's a complete example of analyzing a server and downloading all outputs:

```bash
#!/bin/bash
API_KEY="your-api-key"
BASE_URL="http://localhost:5000"

# 1. Start analysis with 60 seconds of metrics collection
JOB_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/analyze" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "server.example.com",
    "username": "ubuntu",
    "ssh_key": "'"$(cat ~/.ssh/id_rsa)"'",
    "monitor_duration": 60,
    "generate_ansible_full": true,
    "generate_cloud": true
  }')

JOB_ID=$(echo $JOB_RESPONSE | jq -r '.data.job_id')
echo "Started job: $JOB_ID"

# 2. Poll for completion
while true; do
  STATUS=$(curl -s "$BASE_URL/api/v1/jobs/$JOB_ID" \
    -H "X-API-Key: $API_KEY" | jq -r '.data.status')

  echo "Status: $STATUS"

  if [ "$STATUS" = "completed" ]; then
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Job failed!"
    exit 1
  fi

  sleep 10
done

# 3. Download all outputs
curl -H "X-API-Key: $API_KEY" \
  "$BASE_URL/api/v1/jobs/$JOB_ID/outputs/all" \
  -o "server-outputs.zip"

echo "Downloaded: server-outputs.zip"

# 4. Or download specific outputs
curl -H "X-API-Key: $API_KEY" \
  "$BASE_URL/api/v1/jobs/$JOB_ID/outputs/ansible-full" \
  -o "ansible-full.zip"

curl -H "X-API-Key: $API_KEY" \
  "$BASE_URL/api/v1/jobs/$JOB_ID/outputs/terraform-aws" \
  -o "terraform-aws.zip"

echo "Done!"
```

---

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 200 | Success |
| 202 | Accepted (job started) |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (invalid or missing API key) |
| 404 | Not found |
| 500 | Internal server error |
| 503 | Service unavailable (API not configured) |

---

## Rate Limiting

There is currently no rate limiting implemented. For production deployments, consider adding rate limiting via a reverse proxy (nginx, HAProxy) or API gateway.
