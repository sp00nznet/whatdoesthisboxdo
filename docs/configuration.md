# Configuration Guide

## Overview

The System Analyzer can be configured via:
1. Configuration file (`config.json`)
2. Environment variables
3. Command-line arguments

Environment variables take precedence over config file values.

---

## Configuration File

Create a `config.json` in the project root:

```json
{
  "gitlab": {
    "url": "https://gitlab.example.com",
    "token": "glpat-xxxxxxxxxxxx"
  },
  "harbor": {
    "url": "https://harbor.example.com",
    "username": "admin",
    "password": "password"
  },
  "vcenter": {
    "host": "vcenter.example.com",
    "username": "administrator@vsphere.local",
    "password": "password"
  },
  "proxmox": {
    "host": "proxmox.example.com",
    "username": "root@pam",
    "password": "password"
  },
  "output_dir": "output",
  "analyze_users": ["ubuntu", "admin"],
  "vsphere_template": "ubuntu-22.04-template"
}
```

---

## Environment Variables

### GitLab

| Variable | Description |
|----------|-------------|
| `GITLAB_URL` | GitLab server URL |
| `GITLAB_TOKEN` | Personal access token with `read_api` scope |

### Harbor

| Variable | Description |
|----------|-------------|
| `HARBOR_URL` | Harbor registry URL |
| `HARBOR_USERNAME` | Harbor username |
| `HARBOR_PASSWORD` | Harbor password |

### vCenter

| Variable | Description |
|----------|-------------|
| `VCENTER_HOST` | vCenter server hostname |
| `VCENTER_USERNAME` | vCenter username |
| `VCENTER_PASSWORD` | vCenter password |

### Proxmox

| Variable | Description |
|----------|-------------|
| `PROXMOX_HOST` | Proxmox server hostname |
| `PROXMOX_USERNAME` | Proxmox username (e.g., `root@pam`) |
| `PROXMOX_PASSWORD` | Proxmox password |

---

## Command-Line Arguments

```
usage: analyzer.py [-h] [-c CONFIG] [-o OUTPUT] [--analyze-only]
                   [--generate-only] [--analysis-file FILE] [-v]

options:
  -h, --help            Show help message
  -c, --config CONFIG   Path to configuration file (default: config.json)
  -o, --output OUTPUT   Output directory (default: output)
  --analyze-only        Run analysis without generating IaC
  --generate-only       Generate IaC from existing analysis
  --analysis-file FILE  Path to analysis JSON (for --generate-only)
  -v, --verbose         Enable debug logging
```

---

## Configuration Options

### `output_dir`

Directory where all generated files are saved.

**Default:** `output`

### `analyze_users`

List of usernames whose bash history should be analyzed. If empty, all users with login shells are analyzed.

**Default:** `[]` (all users)

**Example:**
```json
{
  "analyze_users": ["ubuntu", "deploy", "admin"]
}
```

### `vsphere_template`

Base vSphere template name used in generated Terraform and Packer configs.

**Default:** `ubuntu-22.04-template`

---

## Credential Security

**Best practices:**

1. Use environment variables for credentials in CI/CD
2. Never commit `config.json` with real credentials
3. Use `.gitignore` to exclude sensitive files (already configured)
4. Consider using a secrets manager for production use

```bash
# Example: Load from a secure vault
export VCENTER_PASSWORD=$(vault kv get -field=password secret/vcenter)
```
