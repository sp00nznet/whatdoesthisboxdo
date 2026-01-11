# What Does This Box Do?

> SSH into any server. Understand its purpose. Recreate it anywhere.

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

A remote system analysis tool that connects to servers via SSH, analyzes them, estimates cloud costs, and generates Infrastructure-as-Code to recreate them.

## Quick Start

```bash
# Run setup script (creates venv and installs dependencies)
./setup.sh
source venv/bin/activate

# Analyze a remote server (with SSH key)
python3 analyzer.py -H server.example.com -u ubuntu -k ~/.ssh/id_rsa

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

## What Gets Generated

| Output | Description |
|--------|-------------|
| `documentation.md` | Server purpose, health assessment, security analysis, troubleshooting |
| `cost-estimate.md` | Annual cost comparison: AWS vs GCP vs Azure |
| `terraform-aws/` | AWS EC2 configuration |
| `terraform-gcp/` | GCP Compute Engine configuration |
| `terraform-azure/` | Azure VM configuration |
| `ansible/` | Playbooks to configure new servers |

### Documentation Includes

- **Executive Summary** - What does this server do? (with confidence score)
- **Health Assessment** - Score out of 100 with warnings and insights
- **Security Checklist** - Firewall, exposed ports, fail2ban, etc.
- **Resource Metrics** - CPU, memory, disk, network with assessments
- **Service Opinions** - Analysis of running services with recommendations
- **Troubleshooting Guide** - Role-specific commands and tips

## Command Reference

### analyzer.py

```
usage: analyzer.py [-h] [-H HOST] [-u USER] [-p PORT] [-k KEY] [--sudo-pass]
                   [--password] [-m SECONDS] [-c CONFIG] [-o OUTPUT]
                   [--analyze-only] [--no-cloud] [--cloud-only] [--cost-only] [-v]

Remote Connection:
  -H, --host HOST      Remote hostname or IP to analyze
  -u, --user USER      SSH username (default: root)
  -p, --port PORT      SSH port (default: 22)
  -k, --key KEY        Path to SSH private key
  --sudo-pass          Prompt for sudo password
  --password           Prompt for SSH password (instead of key)

Monitoring:
  -m, --monitor SECS   Collect metrics over specified duration (e.g., -m 60)

Options:
  -o, --output DIR     Output directory (default: output)
  --analyze-only       Only run analysis, skip generation
  --no-cloud           Skip AWS/GCP/Azure generation
  --cloud-only         Only generate cloud configs
  --cost-only          Only generate cost estimates
  -v, --verbose        Enable debug logging
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
| [Configuration Guide](docs/configuration.md) | Config options |
| [Output Reference](docs/output-reference.md) | Generated files |
| [Cloud Providers](docs/cloud-providers.md) | AWS, GCP, Azure guides |
| [Cost Estimation](docs/cost-estimation.md) | How costs are calculated |

## License

MIT
