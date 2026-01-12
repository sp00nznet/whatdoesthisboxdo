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

<p align="center">
  <img src="https://img.shields.io/badge/Linux-SSH-FCC624.svg" alt="Linux">
  <img src="https://img.shields.io/badge/Windows-WinRM-0078D6.svg" alt="Windows">
  <img src="https://img.shields.io/badge/Local-Analysis-00C853.svg" alt="Local">
</p>

---

A system analysis tool that connects to Linux servers via SSH, Windows servers via WinRM, or analyzes the local system. It estimates cloud costs and generates Infrastructure-as-Code to recreate them.

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
                         ┌──────────────────┐
                         │   TARGET SYSTEM  │
                         ├──────────────────┤
┌──────────────┐   SSH   │  Linux Server    │         ┌──────────────┐
│              │ ──────▶ │                  │         │              │
│    YOUR      │         ├──────────────────┤         │    OUTPUT    │
│  WORKSTATION │  WinRM  │  Windows Server  │ ──────▶ │    FILES     │
│              │ ──────▶ │                  │         │              │
│              │         ├──────────────────┤         └──────────────┘
│              │  Local  │  This Machine    │
│              │ ──────▶ │                  │
└──────────────┘         └──────────────────┘
                              │
                              │ Analyzes:
                              │ • Processes & services
                              │ • Packages & configs
                              │ • Bash/PowerShell history
                              │ • Network connections
                              │ • SSH keys & certificates
                              ▼
         ┌───────────────────────────────────────────────────────┐
         │                   GENERATES                           │
         ├───────────┬───────────┬───────────┬───────────┬──────┤
         │    AWS    │    GCP    │   Azure   │  vSphere  │ Cost │
         │ Terraform │ Terraform │ Terraform │    IaC    │ Est. │
         ├───────────┴───────────┴───────────┴───────────┴──────┤
         │   Scaling Ideas │ Containerization │ Config Tips     │
         └───────────────────────────────────────────────────────┘
```

## Local Analysis

Analyze the current system without any remote connection:

```bash
# Analyze this machine
python3 analyzer.py --local

# With metrics monitoring
python3 analyzer.py --local -m 60

# Output to specific directory
python3 analyzer.py --local -o ./my-analysis
```

## Linux Server Analysis (SSH)

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

## Windows Server Analysis (WinRM)

Analyze Windows servers remotely using WinRM:

```bash
# Basic Windows analysis
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password

# With HTTPS (port 5986)
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password --winrm-ssl

# Custom WinRM port
python3 analyzer.py --windows -H winserver.example.com -u Administrator --password -p 5986

# Using domain credentials
python3 analyzer.py --windows -H winserver.example.com -u 'DOMAIN\Administrator' --password
```

### WinRM Requirements

The target Windows server must have WinRM enabled:

```powershell
# On the Windows target (run as Administrator)
Enable-PSRemoting -Force
winrm quickconfig

# Allow connections from your IP
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "your-workstation-ip"
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
| SSH Keys | Private keys, authorized_keys, known_hosts |
| GPG Keyrings | Public/secret keys, key identities |
| Certificates | PEM/key files in /etc/ssl, /etc/pki |
| GitLab | Repos matching hostname, IaC files, deployments |
| Harbor | Container images matching running containers |
| vCenter/Proxmox | VM configuration, cluster, resource allocation |

## What Gets Generated

| Output | Description |
|--------|-------------|
| `documentation.md` | Server purpose, health assessment, security analysis, recommendations |
| `cost-estimate.md` | Annual cost comparison: AWS vs GCP vs Azure |
| `terraform-aws/` | AWS EC2 configuration |
| `terraform-gcp/` | GCP Compute Engine configuration |
| `terraform-azure/` | Azure VM configuration |
| `ansible/` | Playbooks to configure new servers |

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
- **Scaling Recommendations** - Horizontal vs vertical scaling strategies
- **Containerization Suggestions** - Docker Compose structures, migration steps
- **Configuration Improvements** - Service-specific tuning recommendations

## Command Reference

### analyzer.py

```
usage: analyzer.py [-h] [--local] [--windows] [-H HOST] [-u USER] [-p PORT]
                   [-k KEY] [--sudo-pass] [--password] [--winrm-ssl]
                   [-m SECONDS] [-c CONFIG] [-o OUTPUT]
                   [--analyze-only] [--no-cloud] [--cloud-only] [--cost-only] [-v]

Analysis Mode:
  --local              Analyze the local system (no remote connection)
  --windows            Target is a Windows server (use WinRM instead of SSH)

Remote Connection:
  -H, --host HOST      Remote hostname or IP to analyze
  -u, --user USER      SSH/WinRM username (default: root)
  -p, --port PORT      SSH port (default: 22) or WinRM port (default: 5985)
  -k, --key KEY        Path to SSH private key
  --sudo-pass          Prompt for sudo password (Linux only)
  --password           Prompt for SSH/WinRM password
  --winrm-ssl          Use HTTPS for WinRM connection (port 5986)

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
- For Linux analysis: SSH access to target servers (key or password)
- For Windows analysis: WinRM enabled on target servers
- Sudo/Admin access on target servers (for full analysis)

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

# For Windows server analysis (optional)
pip3 install pywinrm
```

Key packages:
- `paramiko` - SSH connectivity for Linux servers
- `pywinrm` - WinRM connectivity for Windows servers (optional)
- `psutil` - System analysis (optional, for local analysis)
- `requests` - API calls for cost estimation and external sources

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration Guide](docs/configuration.md) | Config options |
| [Output Reference](docs/output-reference.md) | Generated files |
| [Cloud Providers](docs/cloud-providers.md) | AWS, GCP, Azure guides |
| [Cost Estimation](docs/cost-estimation.md) | How costs are calculated |

## License

MIT
