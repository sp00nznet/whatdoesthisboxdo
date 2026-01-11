# Output Reference

## Directory Structure

After running the analyzer, the output directory contains:

```
output/
├── analysis.json            # Raw analysis data
├── documentation.md         # Human-readable system docs
│
├── terraform/               # VM provisioning
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── provider.tf
│   └── terraform.tfvars.example
│
├── ansible/                 # Configuration management
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
│
└── packer/                  # Image building
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

---

## File Descriptions

### `analysis.json`

Raw JSON data from the analysis. Contains:

```json
{
  "timestamp": "2024-01-15T10:30:00",
  "hostname": "webserver-01",
  "processes": {
    "running": [...],
    "services": [...],
    "connections": [...],
    "listening_ports": [...],
    "resource_usage": {...}
  },
  "files": {
    "configurations": [...],
    "installed_packages": [...],
    "service_configs": {...}
  },
  "history": {
    "commands": [...],
    "setup_commands": [...],
    "package_installations": [...]
  },
  "gitlab": {...},
  "harbor": {...},
  "virtualization": {...},
  "summary": {
    "server_purpose": "web_server, database",
    "key_services": [...],
    "potential_issues": [...]
  }
}
```

Use this file to regenerate IaC without re-running analysis:
```bash
python analyzer.py --generate-only --analysis-file output/analysis.json
```

---

### `documentation.md`

Human-readable Markdown documentation including:

- **System Overview** - Server purpose and resource summary
- **Running Services** - Active systemd services
- **Running Processes** - Top processes by CPU/memory
- **Network Configuration** - Listening ports and connections
- **Storage** - Disk usage and important directories
- **Configuration Files** - Service config locations
- **Dependencies** - Installed packages and setup commands
- **Troubleshooting Guide** - Common issues and solutions

---

### Terraform Files

| File | Purpose |
|------|---------|
| `main.tf` | VM resource definition for vSphere |
| `variables.tf` | Input variable declarations |
| `outputs.tf` | Output values (IP, VM ID) |
| `provider.tf` | vSphere provider configuration |
| `terraform.tfvars.example` | Example variable values |

**VM Configuration includes:**
- CPU and memory based on analyzed system
- Disk configuration
- Network settings
- Cloud-init for initial setup

---

### Ansible Files

| File/Directory | Purpose |
|----------------|---------|
| `site.yml` | Main playbook |
| `inventory` | Host inventory file |
| `ansible.cfg` | Ansible configuration |
| `group_vars/all.yml` | Variables for all hosts |

**Roles:**

| Role | Purpose |
|------|---------|
| `common` | Base system configuration |
| `packages` | Install detected packages |
| `services` | Configure and enable services |
| `firewall` | UFW rules for open ports |
| `users` | User account setup |

---

### Packer Files

| File | Purpose |
|------|---------|
| `vsphere.pkr.hcl` | Main Packer template |
| `variables.pkr.hcl` | Variable definitions |
| `auto.pkrvars.hcl.example` | Example values |

**Scripts:**

| Script | Purpose |
|--------|---------|
| `setup.sh` | Base system setup |
| `install-packages.sh` | Install detected packages |
| `cleanup.sh` | Prepare for templating |

**HTTP Directory:**

Cloud-init files for Ubuntu autoinstall:
- `user-data` - Autoinstall configuration
- `meta-data` - Instance metadata (empty)

---

## Customizing Output

The generated IaC is a starting point. You should:

1. **Review** all generated files before use
2. **Adjust** resource sizes as needed
3. **Add** any missing application-specific configuration
4. **Remove** packages or services you don't need
5. **Update** credentials and sensitive values
