# What Does This Box Do?

> Analyze any server. Understand its purpose. Recreate it with code.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/terraform-1.0+-purple.svg" alt="Terraform">
  <img src="https://img.shields.io/badge/ansible-2.9+-red.svg" alt="Ansible">
  <img src="https://img.shields.io/badge/packer-1.8+-orange.svg" alt="Packer">
</p>

---

A system analysis tool that examines servers and generates Infrastructure-as-Code to recreate them.

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
│   YOUR SERVER   │ ──▶ │  SYSTEM ANALYZER │ ──▶ │   IaC OUTPUT    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                │                                │
                        ▼                                ▼                                ▼
                 ┌─────────────┐                 ┌─────────────┐                 ┌─────────────┐
                 │  Terraform  │                 │   Ansible   │                 │   Packer    │
                 │  (vSphere)  │                 │ (Playbooks) │                 │  (Images)   │
                 └─────────────┘                 └─────────────┘                 └─────────────┘
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
| `terraform/` | vSphere VM provisioning configuration |
| `ansible/` | Playbooks and roles to configure the system |
| `packer/` | Templates to build VM images |

## Usage

```bash
# Full analysis + IaC generation
python analyzer.py

# Analysis only (no IaC)
python analyzer.py --analyze-only

# Generate from previous analysis
python analyzer.py --generate-only --analysis-file output/analysis.json

# Custom output directory
python analyzer.py -o ./my-output

# Verbose logging
python analyzer.py -v
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
| [Using the IaC](docs/using-iac.md) | Terraform, Ansible, Packer guides |
| [Architecture](docs/architecture.md) | Module overview and design |

## Requirements

- Python 3.8+
- Root/sudo access (for full analysis)
- Optional: `pyvmomi` (vCenter), `proxmoxer` (Proxmox)

## License

MIT
