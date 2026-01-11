# What Does This Box Do?

> Analyze any server. Understand its purpose. Recreate it anywhere.

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

A system analysis tool that examines servers, estimates cloud costs, and generates Infrastructure-as-Code to recreate them on any platform.

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Configure (optional)
cp config.json.example config.json

# Run
python analyzer.py
```

## What It Does

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   YOUR SERVER   │ ──▶ │  SYSTEM ANALYZER │ ──▶ │     OUTPUT      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                         │
         ┌───────────────────┬───────────────────┬───────┴───────┬───────────────────┐
         │                   │                   │               │                   │
         ▼                   ▼                   ▼               ▼                   ▼
   ┌───────────┐       ┌───────────┐       ┌───────────┐   ┌───────────┐       ┌───────────┐
   │    AWS    │       │    GCP    │       │   Azure   │   │  vSphere  │       │   Cost    │
   │ Terraform │       │ Terraform │       │ Terraform │   │    IaC    │       │ Estimate  │
   └───────────┘       └───────────┘       └───────────┘   └───────────┘       └───────────┘
```

### Analyzes

| Source | What's Collected |
|--------|------------------|
| Processes | Running services, resource usage, open ports |
| Files | Configs, packages, important directories |
| History | Setup commands from bash history |
| GitLab | Related repositories and CI/CD configs |
| Harbor | Container images and scan results |
| vCenter/Proxmox | VM specifications and settings |

### Generates

| Output | Description |
|--------|-------------|
| `documentation.md` | Detailed server docs with troubleshooting guide |
| `cost-estimate.md` | Annual cost comparison across AWS, GCP, Azure |
| `terraform-aws/` | AWS EC2 Terraform configuration |
| `terraform-gcp/` | GCP Compute Engine Terraform configuration |
| `terraform-azure/` | Azure VM Terraform configuration |
| `terraform/` | vSphere VM provisioning configuration |
| `ansible/` | Playbooks and roles to configure the system |
| `packer/` | Templates to build VM images |

## Usage

```bash
# Full analysis + all IaC (including cloud providers)
python analyzer.py

# Skip cloud providers (vSphere only)
python analyzer.py --no-cloud

# Only generate cloud configs + cost estimates
python analyzer.py --cloud-only

# Only generate cost estimates
python analyzer.py --cost-only

# Generate from previous analysis
python analyzer.py --generate-only --analysis-file output/analysis.json

# Custom output directory
python analyzer.py -o ./my-output
```

## Configuration

Set credentials via environment variables or `config.json`:

```bash
# GitLab
export GITLAB_URL="https://gitlab.example.com"
export GITLAB_TOKEN="your-token"

# Harbor
export HARBOR_URL="https://harbor.example.com"
export HARBOR_USERNAME="admin"
export HARBOR_PASSWORD="password"

# vCenter
export VCENTER_HOST="vcenter.example.com"
export VCENTER_USERNAME="administrator@vsphere.local"
export VCENTER_PASSWORD="password"
```

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration Guide](docs/configuration.md) | Detailed config options |
| [Output Reference](docs/output-reference.md) | Understanding generated files |
| [Cloud Providers](docs/cloud-providers.md) | AWS, GCP, Azure deployment guides |
| [Cost Estimation](docs/cost-estimation.md) | How costs are calculated |
| [Using the IaC](docs/using-iac.md) | Terraform, Ansible, Packer guides |
| [Architecture](docs/architecture.md) | Module overview and design |

## Requirements

- Python 3.8+
- Root/sudo access (for full analysis)
- Optional: `pyvmomi` (vCenter), `proxmoxer` (Proxmox)

## License

MIT
