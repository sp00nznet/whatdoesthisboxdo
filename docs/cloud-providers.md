# Cloud Provider Deployment Guide

The System Analyzer generates Terraform configurations for multiple cloud providers. Each configuration is tailored to recreate your analyzed system on the target platform.

---

## Supported Providers

| Provider | Output Directory | Instance Types |
|----------|------------------|----------------|
| AWS | `terraform-aws/` | EC2 (t3, m6i, r6i series) |
| GCP | `terraform-gcp/` | Compute Engine (e2, n2 series) |
| Azure | `terraform-azure/` | Virtual Machines (B, D, E series) |
| vSphere | `terraform/` | VMware VMs |

---

## AWS (Amazon Web Services)

### Generated Files

```
terraform-aws/
├── provider.tf           # AWS provider configuration
├── variables.tf          # Input variables
├── main.tf               # EC2 instance, security group, VPC data
├── outputs.tf            # Instance ID, IPs, SSH command
├── userdata.sh           # Instance initialization script
└── terraform.tfvars.example
```

### Quick Start

```bash
cd output/terraform-aws

# Configure
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply
```

### Required Variables

```hcl
aws_region = "us-east-1"
key_name   = "my-ssh-key"  # Must exist in AWS
```

### Features

- Automatic AMI selection (latest Ubuntu 22.04)
- Security group with detected ports
- Elastic IP allocation
- gp3 SSD storage
- Userdata script for initial setup

### Instance Type Selection

The analyzer maps your system specs to AWS instance types:

| Your Specs | AWS Instance |
|------------|--------------|
| 1 vCPU, 1GB RAM | t3.micro |
| 2 vCPU, 4GB RAM | t3.medium |
| 4 vCPU, 16GB RAM | t3.xlarge |
| 8 vCPU, 32GB RAM | t3.2xlarge |
| High memory | r6i series |
| Balanced | m6i series |

---

## GCP (Google Cloud Platform)

### Generated Files

```
terraform-gcp/
├── provider.tf           # GCP provider configuration
├── variables.tf          # Input variables
├── main.tf               # Compute instance, firewall, SA
├── outputs.tf            # Instance ID, IPs, gcloud command
├── startup-script.sh     # Instance initialization
└── terraform.tfvars.example
```

### Quick Start

```bash
cd output/terraform-gcp

# Authenticate
gcloud auth application-default login

# Configure
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply
```

### Required Variables

```hcl
project_id       = "my-gcp-project"
ssh_pub_key_file = "~/.ssh/id_rsa.pub"
```

### Features

- Latest Ubuntu 22.04 LTS image
- Firewall rules for detected ports
- Service account with cloud-platform scope
- SSD persistent disk
- Startup script for initialization
- **Sustained use discounts** (~30% for full-month usage)

### Machine Type Selection

| Your Specs | GCP Machine Type |
|------------|------------------|
| 1 vCPU, 1GB RAM | e2-micro |
| 2 vCPU, 4GB RAM | e2-medium |
| 4 vCPU, 16GB RAM | e2-standard-4 |
| 8 vCPU, 32GB RAM | e2-standard-8 |
| High memory | e2-highmem series |

---

## Azure (Microsoft Azure)

### Generated Files

```
terraform-azure/
├── provider.tf           # Azure provider configuration
├── variables.tf          # Input variables
├── main.tf               # VM, NSG, VNet, NIC
├── outputs.tf            # VM ID, IPs, SSH command
├── cloud-init.yml        # Cloud-init configuration
└── terraform.tfvars.example
```

### Quick Start

```bash
cd output/terraform-azure

# Authenticate
az login

# Configure
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply
```

### Required Variables

```hcl
location            = "eastus"
ssh_public_key_file = "~/.ssh/id_rsa.pub"
```

### Features

- Creates complete network stack (VNet, Subnet, NSG)
- Network Security Group with detected ports
- Premium SSD storage
- Cloud-init for package installation
- Static public IP option

### VM Size Selection

| Your Specs | Azure VM Size |
|------------|---------------|
| 1 vCPU, 1GB RAM | Standard_B1s |
| 2 vCPU, 4GB RAM | Standard_B2s |
| 4 vCPU, 16GB RAM | Standard_B4ms |
| 8 vCPU, 32GB RAM | Standard_D8s_v5 |
| High memory | Standard_E series |

---

## Comparing Providers

### When to Choose Each Provider

| Choose | When... |
|--------|---------|
| **AWS** | You need the widest service ecosystem, global reach |
| **GCP** | You want sustained use discounts, strong networking |
| **Azure** | You have Microsoft enterprise agreements, Windows workloads |
| **vSphere** | You need on-premises deployment |

### Security Group / Firewall Comparison

All providers get the same detected ports:

```
┌─────────────────┐
│ Detected Ports  │
│  22 (SSH)       │
│  80 (HTTP)      │
│  443 (HTTPS)    │
│  3306 (MySQL)   │
└────────┬────────┘
         │
    ┌────┴────┬────────────┬────────────┐
    ▼         ▼            ▼            ▼
  AWS SG   GCP FW      Azure NSG    vSphere FW
```

---

## Multi-Cloud Deployment

You can deploy to multiple providers simultaneously:

```bash
# Deploy to all three clouds
for provider in aws gcp azure; do
  cd output/terraform-$provider
  terraform init
  terraform apply -auto-approve
  cd ../..
done
```

### Terraform Workspaces

Use workspaces to manage multiple environments:

```bash
cd output/terraform-aws
terraform workspace new production
terraform workspace new staging

terraform workspace select production
terraform apply
```

---

## Cost Optimization Tips

1. **Use Reserved/Committed Instances**
   - AWS: Reserved Instances (30-70% savings)
   - GCP: Committed Use Discounts (up to 57% savings)
   - Azure: Reserved VM Instances (up to 72% savings)

2. **Right-size Instances**
   - Review the cost estimate
   - Start smaller, scale up as needed

3. **Use Spot/Preemptible for Dev**
   - AWS Spot: 60-90% savings
   - GCP Preemptible: 60-91% savings
   - Azure Spot: up to 90% savings

4. **Schedule Start/Stop**
   - Turn off dev instances at night
   - Use auto-scaling for production
