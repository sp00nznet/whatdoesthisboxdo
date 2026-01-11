# Cost Estimation Guide

The System Analyzer provides annual cost estimates for running your analyzed system on AWS, GCP, and Azure. This helps you make informed decisions about cloud migration.

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ System Specs    │ ──▶ │ Instance Mapping │ ──▶ │ Cost Estimate   │
│ - vCPUs         │     │ AWS: t3.large    │     │ AWS:   $X/year  │
│ - Memory        │     │ GCP: e2-standard │     │ GCP:   $Y/year  │
│ - Storage       │     │ Azure: Standard_D│     │ Azure: $Z/year  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Step 1: Extract System Specs

The analyzer reads:
- CPU count from `/proc/cpuinfo` or `psutil`
- Memory from `/proc/meminfo` or `psutil`
- Disk usage from mounted filesystems

### Step 2: Map to Instance Types

Each provider has different instance families. The analyzer finds the smallest instance that meets your requirements:

```python
# Example mapping logic
if vcpus >= 4 and memory_gb >= 16:
    aws_type = "t3.xlarge"
    gcp_type = "e2-standard-4"
    azure_type = "Standard_B4ms"
```

### Step 3: Calculate Costs

```
Monthly Cost = (Hourly Price × 730 hours) + Storage Cost
Annual Cost = Monthly Cost × 12
```

---

## Output Files

### `cost-estimate.md`

Human-readable Markdown report with:
- System specifications
- Provider comparison table
- Detailed breakdowns
- Recommendations

### `cost-estimate.json`

Machine-readable JSON for automation:

```json
{
  "specs": {
    "vcpus": 4,
    "memory_gb": 16.0,
    "storage_gb": 100
  },
  "estimates": {
    "aws": {
      "provider": "AWS",
      "instance_type": "t3.xlarge",
      "region": "us-east-1",
      "hourly_cost": 0.1664,
      "monthly_cost": 129.47,
      "annual_cost": 1553.66
    }
  },
  "cheapest": {...}
}
```

---

## Pricing Data Sources

### Static Pricing (Default)

The analyzer includes built-in pricing tables updated periodically:

| Provider | Pricing Accuracy | Update Frequency |
|----------|------------------|------------------|
| AWS | ~95% | Quarterly |
| GCP | ~95% | Quarterly |
| Azure | ~95% | Quarterly |

### Live Pricing (Azure)

For Azure, the analyzer can fetch live prices from the [Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices):

```python
# No authentication required
GET https://prices.azure.com/api/retail/prices?$filter=...
```

This provides real-time accuracy for Azure estimates.

### AWS Pricing API

AWS pricing requires authentication. For accurate AWS pricing:

```bash
# Use the AWS Price List API
aws pricing get-products --service-code AmazonEC2 --region us-east-1
```

### GCP Pricing

GCP pricing requires the Cloud Billing API:

```bash
gcloud billing catalog
```

---

## What's Included in Estimates

| Cost Component | Included | Notes |
|----------------|----------|-------|
| Compute (on-demand) | Yes | Hourly instance cost |
| Storage (SSD) | Yes | Per-GB monthly cost |
| Data transfer | No | Varies significantly |
| Load balancers | No | Add if needed |
| Reserved discounts | Noted | See recommendations |
| Sustained use (GCP) | Yes | ~30% discount applied |

---

## Instance Type Mapping

### AWS EC2

| vCPUs | Memory | Instance Type | Hourly Cost |
|-------|--------|---------------|-------------|
| 1 | 1 GB | t3.micro | $0.0104 |
| 2 | 2 GB | t3.small | $0.0208 |
| 2 | 4 GB | t3.medium | $0.0416 |
| 2 | 8 GB | t3.large | $0.0832 |
| 4 | 16 GB | t3.xlarge | $0.1664 |
| 8 | 32 GB | t3.2xlarge | $0.3328 |

### GCP Compute Engine

| vCPUs | Memory | Machine Type | Hourly Cost |
|-------|--------|--------------|-------------|
| 1 | 1 GB | e2-micro | $0.0084 |
| 2 | 2 GB | e2-small | $0.0168 |
| 2 | 4 GB | e2-medium | $0.0336 |
| 2 | 8 GB | e2-standard-2 | $0.0671 |
| 4 | 16 GB | e2-standard-4 | $0.1342 |
| 8 | 32 GB | e2-standard-8 | $0.2684 |

### Azure VMs

| vCPUs | Memory | VM Size | Hourly Cost |
|-------|--------|---------|-------------|
| 1 | 1 GB | Standard_B1s | $0.0104 |
| 1 | 2 GB | Standard_B1ms | $0.0207 |
| 2 | 4 GB | Standard_B2s | $0.0416 |
| 2 | 8 GB | Standard_B2ms | $0.0832 |
| 4 | 16 GB | Standard_B4ms | $0.1660 |
| 8 | 32 GB | Standard_D8s_v5 | $0.3840 |

---

## Storage Pricing

### Per GB/Month

| Provider | Standard | SSD | Premium |
|----------|----------|-----|---------|
| AWS | $0.08 (gp3) | $0.10 (gp2) | $0.125 (io1) |
| GCP | $0.04 (pd-std) | $0.10 (pd-bal) | $0.17 (pd-ssd) |
| Azure | $0.05 (Std_LRS) | $0.075 (StdSSD) | $0.15 (Prem_LRS) |

---

## Cost Saving Recommendations

The cost report includes recommendations based on your workload:

### 1. Reserved Instances

| Provider | Commitment | Savings |
|----------|------------|---------|
| AWS | 1 year | 30-40% |
| AWS | 3 year | 50-60% |
| GCP | 1 year | 37% |
| GCP | 3 year | 55% |
| Azure | 1 year | 40% |
| Azure | 3 year | 65% |

### 2. Spot/Preemptible Instances

For fault-tolerant workloads:

| Provider | Instance Type | Savings |
|----------|--------------|---------|
| AWS | Spot | 60-90% |
| GCP | Preemptible | 60-91% |
| GCP | Spot | 60-91% |
| Azure | Spot | up to 90% |

### 3. Right-sizing

The analyzer recommends the minimum instance that fits your specs. Consider:

- Starting with a smaller instance
- Monitoring actual usage
- Scaling up only if needed

---

## Example Output

```markdown
## Cloud Cost Comparison

| Provider | Instance Type | Monthly Cost | Annual Cost |
|----------|--------------|--------------|-------------|
| AWS | t3.large | $68.74 | $824.88 |
| GCP | e2-standard-2 | $54.47 | $653.64 |
| Azure | Standard_B2ms | $68.74 | $824.88 |

### Recommendations

- **Most Cost-Effective**: GCP (e2-standard-2) at $653.64/year
- Consider reserved/committed use for 30-70% additional savings
- Use spot/preemptible instances for non-critical workloads
```

---

## Accuracy Disclaimer

Cost estimates are approximations based on:

- Public on-demand pricing
- Default regions (us-east-1, us-central1, eastus)
- SSD storage
- 730 hours/month (average)

Actual costs may vary due to:

- Regional pricing differences
- Data transfer charges
- Additional services
- Promotional credits
- Enterprise agreements
