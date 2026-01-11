# Using the Generated IaC

This guide covers how to use the generated Terraform, Ansible, and Packer configurations.

---

## Workflow Options

### Option 1: Terraform + Ansible (Recommended)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Terraform   │ ──▶ │   New VM     │ ──▶ │   Ansible    │
│  (Provision) │     │  (Created)   │     │ (Configure)  │
└──────────────┘     └──────────────┘     └──────────────┘
```

1. Use Terraform to create the VM
2. Use Ansible to configure it

### Option 2: Packer + Terraform

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Packer    │ ──▶ │   Template   │ ──▶ │  Terraform   │
│ (Build Image)│     │  (Created)   │     │  (Deploy)    │
└──────────────┘     └──────────────┘     └──────────────┘
```

1. Use Packer to build a pre-configured template
2. Use Terraform to deploy VMs from the template

---

## Terraform

### Prerequisites

- Terraform 1.0+
- vSphere access credentials
- Network access to vCenter

### Setup

```bash
cd output/terraform

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
vim terraform.tfvars
```

**Required variables:**

```hcl
# terraform.tfvars
vsphere_server   = "vcenter.example.com"
vsphere_user     = "administrator@vsphere.local"
vsphere_password = "your-password"

vsphere_datacenter = "Datacenter"
vsphere_cluster    = "Cluster"
vsphere_datastore  = "datastore1"
vsphere_network    = "VM Network"

vm_name     = "my-server"
vm_template = "ubuntu-22.04-template"
```

### Deploy

```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Apply changes
terraform apply

# Get outputs (IP address, etc.)
terraform output
```

### Destroy

```bash
terraform destroy
```

---

## Ansible

### Prerequisites

- Ansible 2.9+
- SSH access to target host
- Python on target host

### Setup

```bash
cd output/ansible

# Edit inventory with your target
vim inventory
```

**Inventory example:**

```ini
[servers]
my-server ansible_host=192.168.1.100 ansible_user=ubuntu

[servers:vars]
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_become=yes
```

### Configure Variables

```bash
vim group_vars/all.yml
```

### Run Playbook

```bash
# Test connection
ansible all -m ping

# Dry run
ansible-playbook site.yml --check

# Apply configuration
ansible-playbook site.yml

# Run specific role
ansible-playbook site.yml --tags packages

# Verbose output
ansible-playbook site.yml -vvv
```

### Available Tags

| Tag | Description |
|-----|-------------|
| `common` | Base system setup |
| `packages` | Package installation |
| `services` | Service configuration |
| `firewall` | Firewall rules |
| `users` | User management |

---

## Packer

### Prerequisites

- Packer 1.8+
- vSphere access credentials
- ISO image in vSphere datastore

### Setup

```bash
cd output/packer

# Copy example variables
cp auto.pkrvars.hcl.example auto.pkrvars.hcl

# Edit with your values
vim auto.pkrvars.hcl
```

**Required variables:**

```hcl
# auto.pkrvars.hcl
vsphere_server   = "vcenter.example.com"
vsphere_user     = "administrator@vsphere.local"
vsphere_password = "your-password"

vsphere_datacenter = "Datacenter"
vsphere_cluster    = "Cluster"
vsphere_datastore  = "datastore1"
vsphere_network    = "VM Network"

iso_paths = ["[datastore1] ISO/ubuntu-22.04-live-server-amd64.iso"]

ssh_username = "ubuntu"
ssh_password = "ubuntu"
```

### Build Image

```bash
# Initialize Packer plugins
packer init .

# Validate template
packer validate .

# Build image
packer build .

# Build with debug
PACKER_LOG=1 packer build .
```

### Output

After successful build:
- New VM template in vSphere
- `manifest.json` with build details

---

## Combined Workflow Example

### Step 1: Build Template with Packer

```bash
cd output/packer
packer build .
# Note the template name from output
```

### Step 2: Deploy with Terraform

```bash
cd output/terraform

# Update terraform.tfvars with new template name
vim terraform.tfvars

terraform init
terraform apply
```

### Step 3: Additional Config with Ansible

```bash
cd output/ansible

# Update inventory with new VM IP
vim inventory

ansible-playbook site.yml
```

---

## Troubleshooting

### Terraform

| Issue | Solution |
|-------|----------|
| Connection timeout | Check network/firewall to vCenter |
| Permission denied | Verify vSphere credentials and permissions |
| Template not found | Check template name and folder path |

### Ansible

| Issue | Solution |
|-------|----------|
| SSH connection failed | Verify SSH key and host accessibility |
| Sudo password required | Add `ansible_become_pass` or use `--ask-become-pass` |
| Package not found | Check package name for your OS version |

### Packer

| Issue | Solution |
|-------|----------|
| ISO not found | Verify ISO path in datastore |
| SSH timeout | Increase `ssh_timeout`, check boot command |
| Build hangs | Enable `PACKER_LOG=1` for debugging |
