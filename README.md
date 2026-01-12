# What Does This Box Do?

> Analyze any server - local, remote Linux (SSH), or Windows (WinRM). Understand its purpose. Recreate it anywhere.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/terraform-1.0+-purple.svg" alt="Terraform">
  <img src="https://img.shields.io/badge/ansible-2.9+-red.svg" alt="Ansible">
  <img src="https://img.shields.io/badge/packer-1.8+-orange.svg" alt="Packer">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/AWS-EC2-FF9900.svg" alt="AWS">
  <img src="https://img.shields.io/badge/GCP-Compute-4285F4.svg" alt="GCP">
  <img src="https://img.shields.io/badge/Azure-VM-0078D4.svg" alt="Azure">
  <img src="https://img.shields.io/badge/vSphere-VM-607078.svg" alt="vSphere">
</p>

---

A system analysis tool that connects to local or remote servers (Linux via SSH, Windows via WinRM), analyzes them, estimates cloud costs, and generates Infrastructure-as-Code to recreate them.

## Quick Start

```bash
# Run setup script (creates venv and installs dependencies)
./setup.sh
source venv/bin/activate

# Analyze the local system
python3 analyzer.py --local

# Analyze a remote Linux server (with SSH key)
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa

# Analyze a remote Windows server (WinRM)
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password

# Analyze with password authentication
python3 analyzer.py -H server.example.com -u admin --password

# Batch analyze from CSV
python3 batch_processor.py servers.csv -k ~/.ssh/id_rsa
```

## How It Works

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  YOUR        │   SSH   │    REMOTE    │         │    OUTPUT    │
│  WORKSTATION │ ──────▶ │    SERVER    │ ──────▶ │    FILES     │
└──────────────┘         └──────────────┘         └──────────────┘
                              │
                              │ Analyzes:
                              │ • Processes & services
                              │ • Packages & configs
                              │ • Bash history
                              │ • Network connections
                              ▼
         ┌───────────────────────────────────────────────────────┐
         │                   GENERATES                           │
         ├───────────┬───────────┬───────────┬───────────┬──────┤
         │    AWS    │    GCP    │   Azure   │  vSphere  │ Cost │
         │ Terraform │ Terraform │ Terraform │    IaC    │ Est. │
         └───────────┴───────────┴───────────┴───────────┴──────┘
```

## Single Server Analysis

```bash
# Basic remote analysis (with SSH key)
python3 analyzer.py -H 192.168.1.100 -u ubuntu -k ~/.ssh/id_rsa

# With password authentication (no key needed)
python3 analyzer.py -H 192.168.1.100 -u admin --password

# With metrics monitoring (60 seconds) for better usage insights
python3 analyzer.py -H 192.168.1.100 -u ubuntu -k ~/.ssh/id_rsa -m 60

# Extended monitoring (5 minutes) for thorough analysis
python3 analyzer.py -H 192.168.1.100 -u ubuntu -k ~/.ssh/id_rsa -m 300

# With sudo password prompt
python3 analyzer.py -H server.example.com -u admin -k ~/.ssh/id_rsa --sudo-pass

# Password auth with sudo password
python3 analyzer.py -H server.example.com -u admin --password --sudo-pass

# Custom SSH port
python3 analyzer.py -H server.example.com -u root -k ~/.ssh/id_rsa -p 2222

# Output to specific directory
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa -o ./results
```

## Local Analysis

Analyze the current system without any remote connection:

```bash
# Analyze local system
python3 analyzer.py --local

# Local analysis with metrics monitoring
python3 analyzer.py --local -m 60

# Local analysis to specific output directory
python3 analyzer.py --local -o ./my-server-analysis
```

## Windows Server Analysis

Analyze Windows servers using WinRM (Windows Remote Management):

```bash
# Basic Windows analysis
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password

# Windows with HTTPS (port 5986)
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password --winrm-ssl

# Custom WinRM port
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password -p 5985
```

**Windows Prerequisites:**
- WinRM must be enabled on the target server
- Install pywinrm: `pip3 install pywinrm`

Enable WinRM on Windows (run as Administrator):
```powershell
winrm quickconfig
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
```

## Metrics Monitoring

Use the `-m/--monitor` option to collect metrics over time for more accurate analysis:

```bash
# Monitor for 60 seconds (good for quick assessment)
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa -m 60

# Monitor for 5 minutes (better for production servers)
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa -m 300
```

The monitor collects:
- CPU usage (average, min, max)
- Memory usage patterns
- Disk I/O rates
- Network throughput
- Top resource-consuming processes

Results include:
- **Health Score** (0-100) with assessment
- **Insights** about resource usage patterns
- **Warnings** for potential issues
- **Recommendations** for optimization

## Web Interface

Run the web interface for a user-friendly way to analyze servers and download outputs.

### Quick Start with Docker

```bash
# Start the web interface
docker-compose up -d

# Access at http://localhost:5000
```

### Web Interface Features

- **Single Server Analysis** - Enter connection details or use saved credentials
- **Batch Processing** - Upload CSV files to analyze multiple servers
- **Metrics Monitoring** - Configure real-time metrics collection duration
- **Generation Options** - Choose which outputs to generate:
  - Basic Ansible playbooks
  - Full Ansible system recreation playbooks
  - vSphere Terraform configuration
  - Cloud provider configs (AWS, GCP, Azure)
- **Downloadable Outputs** - Download all generated files as ZIP:
  - Individual Terraform configs per provider
  - Combined Terraform package
  - Ansible playbooks
  - Complete output bundle
- **Job Management** - Track analysis progress and view results
- **Credential Management** - Save and reuse SSH/WinRM credentials
- **Admin Dashboard** - Manage credentials and environment variables

### Running Locally

```bash
# Install dependencies
pip3 install flask

# Set environment variables
export FLASK_SECRET_KEY="your-secret-key"
export API_KEY="your-api-key"  # Required for REST API

# Run the web server
cd web
python3 app.py
```

---

## REST API

The web interface includes a REST API for programmatic access. All endpoints require an API key.

### Quick Examples

```bash
# Start an analysis with metrics monitoring
curl -X POST http://localhost:5000/api/v1/analyze \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "server.example.com",
    "username": "ubuntu",
    "ssh_key": "...",
    "monitor_duration": 60,
    "generate_ansible_full": true,
    "generate_cloud": true
  }'

# Check job status
curl http://localhost:5000/api/v1/jobs/<job_id> \
  -H "X-API-Key: YOUR_KEY"

# Download Ansible playbooks
curl http://localhost:5000/api/v1/jobs/<job_id>/outputs/ansible-full \
  -H "X-API-Key: YOUR_KEY" \
  -o ansible-full.zip

# Download all Terraform configs
curl http://localhost:5000/api/v1/jobs/<job_id>/outputs/all-terraform \
  -H "X-API-Key: YOUR_KEY" \
  -o terraform.zip
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze` | POST | Start single server analysis |
| `/api/v1/batch` | POST | Start batch analysis |
| `/api/v1/jobs` | GET | List all jobs |
| `/api/v1/jobs/<id>` | GET | Get job status and details |
| `/api/v1/jobs/<id>/result` | GET | Get analysis result data |
| `/api/v1/jobs/<id>/outputs` | GET | List available outputs |
| `/api/v1/jobs/<id>/outputs/<type>` | GET | Download output as ZIP |
| `/api/v1/outputs` | GET | List all output directories |
| `/api/v1/outputs/<dir>/<type>` | GET | Download output as ZIP |
| `/api/v1/docs` | GET | List documentation files |
| `/api/v1/docs/<filename>` | GET | Download documentation |
| `/api/v1/credentials` | GET/POST | List/create credentials |

### Analysis Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `monitor_duration` | int | 0 | Metrics collection duration in seconds |
| `generate_ansible` | bool | true | Generate basic Ansible playbooks |
| `generate_ansible_full` | bool | true | Generate full recreation playbooks |
| `generate_terraform` | bool | true | Generate vSphere Terraform |
| `generate_cloud` | bool | true | Generate AWS/GCP/Azure configs |

See [API Reference](docs/api-reference.md) for complete documentation.

---

## Batch Processing (CSV)

Analyze multiple servers at once using a CSV file.

### Generate CSV Template

```bash
python3 batch_processor.py --template
# Creates: servers.csv
```

### CSV Format

```csv
hostname,username,port,private_key,sudo_password,groups,notes
server1.example.com,ubuntu,22,~/.ssh/id_rsa,,web,Production web server
server2.example.com,admin,22,~/.ssh/id_rsa,sudopass,db,Database server
192.168.1.100,root,22,~/.ssh/id_ed25519,,internal,Internal server
```

### Run Batch Analysis

```bash
# Sequential processing
python3 batch_processor.py servers.csv -k ~/.ssh/id_rsa

# Parallel processing (4 servers at once)
python3 batch_processor.py servers.csv -k ~/.ssh/id_rsa -p 4

# Skip cloud generation
python3 batch_processor.py servers.csv -k ~/.ssh/id_rsa --no-cloud
```

### Batch Output

```
output/
├── batch-summary.md          # Overview of all servers
├── batch-summary.json        # Machine-readable summary
├── server1.example.com/
│   ├── analysis.json
│   ├── documentation.md
│   ├── cost-estimate.md
│   ├── terraform-aws/
│   ├── terraform-gcp/
│   └── terraform-azure/
├── server2.example.com/
│   └── ...
└── 192.168.1.100/
    └── ...
```

## What Gets Analyzed

| Source | Data Collected |
|--------|----------------|
| Processes | Running services, CPU/memory usage, open ports |
| Packages | Installed apt/yum/pip packages |
| Configs | Service configurations in /etc |
| History | Setup commands from bash_history |
| Network | Listening ports, active connections |
| Storage | Disk usage, important directories |
| SSH Keys | Private keys, authorized_keys, known_hosts |
| GPG Keyrings | Public/secret keys, key identities |
| Certificates | PEM/key files in /etc/ssl, /etc/pki |
| GitLab | Repos matching hostname, IaC files, deployments |
| Harbor | Container images matching running containers |
| vCenter/Proxmox | VM configuration, cluster, resource allocation |

## What Gets Generated

| Output | Description |
|--------|-------------|
| `documentation.md` | Server purpose, health assessment, security analysis, troubleshooting |
| `cost-estimate.md` | Annual cost comparison: AWS vs GCP vs Azure |
| `terraform-aws/` | AWS EC2 configuration |
| `terraform-gcp/` | GCP Compute Engine configuration |
| `terraform-azure/` | Azure VM configuration |
| `ansible/` | Basic playbooks to configure new servers |
| `ansible-full/` | Comprehensive playbooks for full system recreation |

## Full System Recreation with Ansible

The tool generates comprehensive Ansible playbooks (`ansible-full/`) that can recreate a system exactly as it was, including:

| Component | What Gets Recreated |
|-----------|---------------------|
| Users & Groups | All user accounts, group memberships, passwords (hashed), shell configs, SSH keys |
| Packages | System packages (apt/yum), pip packages, npm globals, snaps |
| Services | Systemd services, custom unit files, enabled/running states |
| Docker | Docker installation, containers, images, networks, volumes, compose files |
| Filesystem | Mount points (fstab), NFS/CIFS mounts, directory structures |
| Cron Jobs | User crontabs, /etc/cron.d files, scheduled tasks |
| Network | Hostname, /etc/hosts, firewall rules (UFW), netplan configs |
| Configuration | SSH config, sudoers, sysctl, system limits, environment variables |
| Secrets | GPG keyrings, SSH private keys, SSH host keys (with security flags) |

### Generate Full Ansible Playbooks Only

```bash
# Generate only comprehensive Ansible playbooks
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa --ansible-full-only

# Skip full ansible generation (use basic only)
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa --no-ansible-full
```

### Using the Generated Ansible Playbooks

```bash
cd output/server.example.com/ansible-full/

# Review and customize variables
vim group_vars/all.yml

# Check syntax
./check-syntax.sh

# Dry run (no changes)
./dryrun.sh <target_host>

# Deploy full system
./deploy.sh <target_host>
```

### Run Specific Roles

```bash
# Only recreate users
ansible-playbook -i inventory site.yml --tags "users"

# Only install packages
ansible-playbook -i inventory site.yml --tags "packages"

# Only configure Docker
ansible-playbook -i inventory site.yml --tags "docker"

# Only filesystem (directories + mounts)
ansible-playbook -i inventory site.yml --tags "filesystem"

# Only restore GPG keyrings and SSH keys
ansible-playbook -i inventory site.yml --tags "secrets" \
  -e "import_gpg_secret_keys=true" \
  -e "copy_ssh_private_keys=true"
```

## System State Collection Script

For manual data collection or offline analysis, use the included bash script:

```bash
# Run on the source server
./scripts/collect_system_state.sh [output_dir]

# Example
sudo ./scripts/collect_system_state.sh /tmp/system_state
```

This collects:
- User accounts and password hashes
- Group memberships
- All installed packages (apt, pip, npm, snap)
- Running services and custom unit files
- Cron jobs
- Docker containers, images, networks, volumes
- Mount points and fstab
- Directory structures (/opt, /srv, /var/www, etc.)
- Network configuration and firewall rules
- System configuration files
- GPG keyrings (public and secret keys exported)
- SSH private keys and host keys

### Documentation Includes

- **Executive Summary** - What does this server do? (with confidence score)
- **External Sources Status** - GitLab, Harbor, vCenter/Proxmox connection status
- **GitLab Analysis** - Related repos, IaC files, recent deployments
- **Harbor Analysis** - Container images matched to running containers
- **Health Assessment** - Score out of 100 with warnings and insights
- **SSH Keys & Credentials** - Private keys, GPG keyrings, authorized access
- **Security Checklist** - Firewall, exposed ports, fail2ban, etc.
- **Resource Metrics** - CPU, memory, disk, network with assessments
- **Service Opinions** - Analysis of running services with recommendations
- **Scaling Recommendations** - Capacity analysis and scaling strategies
- **Containerization Suggestions** - Docker migration guidance

### Scaling Analysis

The documentation includes intelligent scaling recommendations based on detected workloads:

**Capacity Analysis**
- Current CPU/memory utilization assessment
- Headroom calculation for growth
- Resource bottleneck identification

**Scaling Strategies by Service Type**

| Service Type | Recommended Strategy |
|--------------|---------------------|
| Web Servers (nginx, Apache) | Horizontal scaling with load balancer |
| Stateless Apps (Node, Python) | Auto-scaling based on CPU/request metrics |
| Databases (MySQL, PostgreSQL) | Vertical scaling first, then read replicas |
| Container Hosts | Kubernetes/Swarm orchestration |

**Includes:**
- Load balancer setup guidance
- Auto-scaling trigger recommendations (scale at 70% CPU, scale in at 30%)
- Session management for stateless scaling
- Database-specific strategies (read replicas, sharding, connection pooling)
- Capacity planning projections

### Containerization Analysis

Identifies services suitable for containerization and generates migration guidance:

**Service Detection**
- Analyzes running services against known containerizable patterns
- Recommends appropriate base images (Alpine variants for smaller footprint)
- Identifies port mappings and volume requirements

**Generated Artifacts**

```yaml
# Example output for detected services
services:
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"

  postgresql:
    image: postgres:15-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
```

**Recommendations Include:**
- Base image selection (official images, Alpine variants)
- Multi-stage build suggestions for compiled languages
- Volume strategies for databases
- Network configuration for service communication
- Migration pros/cons assessment

## Command Reference

### analyzer.py

```
usage: analyzer.py [-h] [--local] [--windows] [-H HOST] [-u USER] [-p PORT]
                   [-k KEY] [--sudo-pass] [--password] [--winrm-ssl]
                   [-m SECONDS] [-c CONFIG] [-o OUTPUT] [--analyze-only]
                   [--generate-only] [--analysis-file FILE] [--no-cloud]
                   [--cloud-only] [--cost-only] [--ansible-full-only]
                   [--no-ansible-full] [-v]

Analysis Mode:
  --local                 Analyze the local system (no remote connection)
  --windows               Target is a Windows server (use WinRM instead of SSH)

Remote Connection:
  -H, --host HOST         Remote hostname or IP to analyze
  -u, --user USER         SSH/WinRM username (default: root)
  -p, --port PORT         SSH port (default: 22) or WinRM port (default: 5985)
  -k, --key KEY           Path to SSH private key
  --sudo-pass             Prompt for sudo password (Linux only)
  --password              Prompt for SSH/WinRM password
  --winrm-ssl             Use HTTPS for WinRM connection (port 5986)

Monitoring:
  -m, --monitor SECS      Collect metrics over specified duration (e.g., -m 60)

Options:
  -o, --output DIR        Output directory (default: output)
  --analyze-only          Only run analysis, skip generation
  --generate-only         Skip analysis, only generate from existing data
  --analysis-file FILE    Path to existing analysis JSON (for --generate-only)
  --no-cloud              Skip AWS/GCP/Azure generation
  --cloud-only            Only generate cloud configs
  --cost-only             Only generate cost estimates
  --ansible-full-only     Only generate comprehensive Ansible playbooks
  --no-ansible-full       Skip comprehensive Ansible generation
  -v, --verbose           Enable debug logging
```

### batch_processor.py

```
usage: batch_processor.py [-h] [-o OUTPUT] [-k KEY] [-p PARALLEL]
                          [--no-cloud] [--template] [-v] [csv_file]

Arguments:
  csv_file             Path to CSV file with server list

Options:
  -o, --output DIR     Output directory (default: output)
  -k, --key KEY        Default SSH private key path
  -p, --parallel N     Number of parallel connections (default: 1)
  --no-cloud           Skip cloud provider generation
  --template           Generate a CSV template file
  -v, --verbose        Enable debug logging
```

## External Data Sources

Configure optional external sources in `.env` for enhanced analysis:

```bash
# Copy example and edit
cp .env.example .env
```

### Supported Sources

| Source | Purpose | Required Variables |
|--------|---------|-------------------|
| GitLab | Match paths to repos, find IaC | `GITLAB_URL`, `GITLAB_TOKEN` |
| Harbor | Match containers to registry | `HARBOR_URL`, `HARBOR_USERNAME`, `HARBOR_PASSWORD` |
| vCenter | VM configuration details | `VCENTER_HOST`, `VCENTER_USERNAME`, `VCENTER_PASSWORD` |
| Proxmox | VM/container details | `PROXMOX_HOST`, `PROXMOX_USERNAME`, `PROXMOX_PASSWORD` |

If credentials are not provided, the analysis will note which sources were unavailable.

## Requirements

- Python 3.8+
- SSH access to target servers (key or password)
- Sudo access on target servers (for full analysis)

### System Prerequisites (Debian/Ubuntu)

```bash
# Install python3-venv (required for virtual environment)
sudo apt install python3-venv

# Or for a specific Python version (e.g., 3.13)
sudo apt install python3.13-venv
```

### Python Dependencies

```bash
# Recommended: Use a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip3 install -r requirements.txt
```

Key packages:
- `paramiko` - SSH connectivity
- `psutil` - System analysis (optional, for local analysis)
- `requests` - API calls for cost estimation

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/api-reference.md) | REST API v1 complete documentation |
| [Ansible Full Recreation](docs/ansible-full-recreation.md) | Complete system recreation guide |
| [Configuration Guide](docs/configuration.md) | Config options |
| [Output Reference](docs/output-reference.md) | Generated files |
| [Cloud Providers](docs/cloud-providers.md) | AWS, GCP, Azure guides |
| [Cost Estimation](docs/cost-estimation.md) | How costs are calculated |

## License

MIT
