# Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         analyzer.py                              │
│                      (Main Orchestrator)                         │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   Analyzers   │       │  Connectors   │       │  Generators   │
└───────────────┘       └───────────────┘       └───────────────┘
```

---

## Module Structure

```
whatdoesthisboxdo/
├── analyzer.py              # Entry point and orchestration
│
├── analyzers/               # Local system analysis
│   ├── process_analyzer.py
│   ├── file_analyzer.py
│   └── history_analyzer.py
│
├── connectors/              # External service integration
│   ├── gitlab_connector.py
│   ├── harbor_connector.py
│   ├── vcenter_connector.py
│   └── proxmox_connector.py
│
├── generators/              # IaC output generation
│   ├── doc_generator.py
│   ├── terraform_generator.py
│   ├── ansible_generator.py
│   └── packer_generator.py
│
└── docs/                    # Documentation
```

---

## Analyzers

### ProcessAnalyzer

**Purpose:** Collect information about running processes and system resources.

**Data Collected:**
- Running processes (name, PID, user, CPU/memory usage)
- Systemd services and their status
- Network connections and listening ports
- System resource usage (CPU, memory, disk, network I/O)

**Dependencies:**
- `psutil` (optional, falls back to system commands)

```python
from analyzers.process_analyzer import ProcessAnalyzer

analyzer = ProcessAnalyzer()
data = analyzer.analyze()
# Returns: {running: [], services: [], connections: [], resource_usage: {}}
```

---

### FileAnalyzer

**Purpose:** Analyze files, configurations, and installed packages.

**Data Collected:**
- Configuration files in `/etc`
- Installed packages (apt, pip, npm)
- Service-specific config locations
- Recently modified files

```python
from analyzers.file_analyzer import FileAnalyzer

analyzer = FileAnalyzer()
data = analyzer.analyze()
# Returns: {configurations: [], installed_packages: [], service_configs: {}}
```

---

### HistoryAnalyzer

**Purpose:** Extract setup commands from bash history.

**Data Collected:**
- All commands from user histories
- Package installation commands
- Service configuration commands
- Filtered setup-relevant commands

```python
from analyzers.history_analyzer import HistoryAnalyzer

analyzer = HistoryAnalyzer(users=['ubuntu', 'admin'])
data = analyzer.analyze()
# Returns: {commands: [], setup_commands: [], package_installations: []}
```

---

## Connectors

### GitLabConnector

**Purpose:** Scan GitLab for related repositories.

**Features:**
- List accessible projects
- Search for hostname-related repos
- Extract CI/CD configuration

```python
from connectors.gitlab_connector import GitLabConnector

connector = GitLabConnector(url, token)
data = connector.scan_repos()
```

---

### HarborConnector

**Purpose:** Scan Harbor container registry.

**Features:**
- List projects and repositories
- Get image tags and digests
- Retrieve vulnerability scan results

```python
from connectors.harbor_connector import HarborConnector

connector = HarborConnector(url, username, password)
data = connector.scan_registry()
```

---

### VCenterConnector

**Purpose:** Connect to VMware vCenter.

**Features:**
- Get VM specifications
- Retrieve network configuration
- Extract disk and storage info

**Dependencies:** `pyvmomi`

```python
from connectors.vcenter_connector import VCenterConnector

connector = VCenterConnector(host, username, password)
data = connector.get_vm_info()
```

---

### ProxmoxConnector

**Purpose:** Connect to Proxmox VE.

**Features:**
- List VMs and containers
- Get node information
- Retrieve storage and network config

**Dependencies:** `proxmoxer` (optional)

```python
from connectors.proxmox_connector import ProxmoxConnector

connector = ProxmoxConnector(host, username, password)
data = connector.get_vm_info()
```

---

## Generators

### DocumentationGenerator

**Input:** Analysis data dictionary

**Output:** Markdown file with:
- System overview
- Service documentation
- Network configuration
- Troubleshooting guide

---

### TerraformGenerator

**Input:** Analysis data + vSphere template name

**Output:** Terraform configuration:
- `main.tf` - VM resource
- `variables.tf` - Input variables
- `outputs.tf` - Output values
- `provider.tf` - Provider config

---

### AnsibleGenerator

**Input:** Analysis data

**Output:** Ansible project:
- `site.yml` - Main playbook
- `roles/` - Configuration roles
- `inventory` - Host inventory
- `group_vars/` - Variables

---

### PackerGenerator

**Input:** Analysis data + vSphere template name

**Output:** Packer configuration:
- HCL template files
- Provisioning scripts
- Cloud-init config

---

## Data Flow

```
1. ANALYSIS PHASE
   ┌──────────────┐
   │ ProcessAnalyzer │──┐
   └──────────────┘    │
   ┌──────────────┐    │    ┌──────────────┐
   │ FileAnalyzer │────┼───▶│ analysis_data │
   └──────────────┘    │    └──────────────┘
   ┌──────────────┐    │
   │HistoryAnalyzer│──┘
   └──────────────┘

2. ENRICHMENT PHASE (Optional)
   ┌──────────────┐
   │GitLabConnector│──┐
   └──────────────┘   │
   ┌──────────────┐   │    ┌──────────────┐
   │HarborConnector│──┼───▶│ analysis_data │
   └──────────────┘   │    │  (enriched)   │
   ┌──────────────┐   │    └──────────────┘
   │VCenter/Proxmox│──┘
   └──────────────┘

3. GENERATION PHASE
   ┌──────────────┐         ┌──────────────┐
   │ analysis_data │───────▶│  Generators  │
   └──────────────┘         └──────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
   ┌───────────┐           ┌───────────┐           ┌───────────┐
   │ Terraform │           │  Ansible  │           │  Packer   │
   └───────────┘           └───────────┘           └───────────┘
```

---

## Extending

### Adding a New Analyzer

1. Create `analyzers/my_analyzer.py`
2. Implement `analyze()` method returning a dict
3. Import in `analyzer.py`
4. Call from `run_full_analysis()`

### Adding a New Connector

1. Create `connectors/my_connector.py`
2. Implement connection and data retrieval methods
3. Import in `analyzer.py`
4. Add configuration options

### Adding a New Generator

1. Create `generators/my_generator.py`
2. Implement `generate(output_path)` method
3. Import in `analyzer.py`
4. Call from `generate_all()`
