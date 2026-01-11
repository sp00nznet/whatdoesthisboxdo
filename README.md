# System Analyzer Tool

A comprehensive system analysis tool that examines existing servers and generates documentation along with Infrastructure-as-Code to recreate them.

## Features

- **System Analysis**
  - Running processes and services
  - Network connections and listening ports
  - File and configuration analysis
  - Bash history analysis for setup commands
  - Package installation tracking

- **Infrastructure Integration**
  - GitLab repository scanning
  - Harbor container registry scanning
  - VMware vCenter integration
  - Proxmox VE integration

- **Output Generation**
  - Detailed system documentation (Markdown)
  - Terraform configurations for vSphere
  - Ansible playbooks and roles
  - Packer templates for VM image creation

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd whatdoesthisboxdo

# Install dependencies
pip install -r requirements.txt

# Optional: Install vCenter support
pip install pyvmomi

# Optional: Install Proxmox support
pip install proxmoxer
```

## Configuration

Copy the example configuration and edit it:

```bash
cp config.json.example config.json
```

Or use environment variables:

```bash
export GITLAB_URL="https://gitlab.example.com"
export GITLAB_TOKEN="your-token"
export HARBOR_URL="https://harbor.example.com"
export HARBOR_USERNAME="admin"
export HARBOR_PASSWORD="password"
export VCENTER_HOST="vcenter.example.com"
export VCENTER_USERNAME="administrator@vsphere.local"
export VCENTER_PASSWORD="password"
```

## Usage

### Full Analysis and Generation

```bash
# Run full analysis with default config
python analyzer.py

# Run with custom config
python analyzer.py -c /path/to/config.json

# Run with custom output directory
python analyzer.py -o /path/to/output

# Verbose output
python analyzer.py -v
```

### Analysis Only

```bash
# Only analyze, don't generate IaC
python analyzer.py --analyze-only
```

### Generate from Existing Analysis

```bash
# Generate IaC from a previous analysis
python analyzer.py --generate-only --analysis-file output/analysis.json
```

## Output Structure

```
output/
├── analysis.json           # Raw analysis data
├── documentation.md        # System documentation
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── provider.tf
│   └── terraform.tfvars.example
├── ansible/
│   ├── site.yml
│   ├── inventory
│   ├── ansible.cfg
│   ├── group_vars/
│   │   └── all.yml
│   └── roles/
│       ├── common/
│       ├── packages/
│       ├── services/
│       ├── firewall/
│       └── users/
└── packer/
    ├── vsphere.pkr.hcl
    ├── variables.pkr.hcl
    ├── auto.pkrvars.hcl.example
    ├── scripts/
    │   ├── setup.sh
    │   ├── install-packages.sh
    │   └── cleanup.sh
    └── http/
        ├── user-data
        └── meta-data
```

## Using Generated IaC

### Terraform

```bash
cd output/terraform

# Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Initialize and apply
terraform init
terraform plan
terraform apply
```

### Ansible

```bash
cd output/ansible

# Edit inventory with target host
vim inventory

# Run playbook
ansible-playbook site.yml
```

### Packer

```bash
cd output/packer

# Copy and edit variables
cp auto.pkrvars.hcl.example auto.pkrvars.hcl
vim auto.pkrvars.hcl

# Build image
packer init .
packer build .
```

## Requirements

- Python 3.8+
- Root/sudo access (for analyzing bash histories and system files)
- Network access to GitLab/Harbor/vCenter/Proxmox (if using those features)

## Module Overview

### Analyzers

- `process_analyzer.py` - Analyzes running processes, services, and connections
- `file_analyzer.py` - Analyzes configuration files and packages
- `history_analyzer.py` - Analyzes bash histories for setup commands

### Connectors

- `gitlab_connector.py` - Scans GitLab repositories
- `harbor_connector.py` - Scans Harbor container registry
- `vcenter_connector.py` - Connects to VMware vCenter
- `proxmox_connector.py` - Connects to Proxmox VE

### Generators

- `doc_generator.py` - Generates Markdown documentation
- `terraform_generator.py` - Generates Terraform configurations
- `ansible_generator.py` - Generates Ansible playbooks
- `packer_generator.py` - Generates Packer templates

## License

MIT License
