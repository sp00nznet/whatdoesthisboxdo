"""
Cloud Cost Estimator
Estimates annual costs for running VMs on AWS, GCP, and Azure
Uses public pricing data and free pricing APIs where available
"""

import json
import logging
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class VMSpecs:
    """VM specifications for cost estimation"""
    vcpus: int
    memory_gb: float
    storage_gb: int
    instance_type: str = ""
    region: str = ""


@dataclass
class CostEstimate:
    """Cost estimate result"""
    provider: str
    instance_type: str
    region: str
    hourly_cost: float
    monthly_cost: float
    annual_cost: float
    currency: str = "USD"
    details: Dict = None

    def to_dict(self) -> Dict:
        return {
            'provider': self.provider,
            'instance_type': self.instance_type,
            'region': self.region,
            'hourly_cost': round(self.hourly_cost, 4),
            'monthly_cost': round(self.monthly_cost, 2),
            'annual_cost': round(self.annual_cost, 2),
            'currency': self.currency,
            'details': self.details or {}
        }


class CostEstimator:
    """Estimates cloud costs for different providers"""

    # Approximate on-demand pricing (USD/hour) - Updated Jan 2024
    # These are baseline prices for us-east-1/us-central1/eastus
    AWS_PRICING = {
        't3.micro': 0.0104,
        't3.small': 0.0208,
        't3.medium': 0.0416,
        't3.large': 0.0832,
        't3.xlarge': 0.1664,
        't3.2xlarge': 0.3328,
        'm6i.large': 0.096,
        'm6i.xlarge': 0.192,
        'm6i.2xlarge': 0.384,
        'm6i.4xlarge': 0.768,
        'm6i.8xlarge': 1.536,
        'm6i.12xlarge': 2.304,
        'm6i.16xlarge': 3.072,
        'r6i.large': 0.126,
        'r6i.xlarge': 0.252,
        'r6i.2xlarge': 0.504,
        'r6i.4xlarge': 1.008,
    }

    GCP_PRICING = {
        'e2-micro': 0.0084,
        'e2-small': 0.0168,
        'e2-medium': 0.0336,
        'e2-standard-2': 0.0671,
        'e2-standard-4': 0.1342,
        'e2-standard-8': 0.2684,
        'e2-standard-16': 0.5765,
        'e2-standard-32': 1.0729,
        'e2-highmem-2': 0.0908,
        'e2-highmem-4': 0.1816,
        'e2-highmem-8': 0.3631,
        'e2-highmem-16': 0.7262,
        'n2-standard-2': 0.0971,
        'n2-standard-4': 0.1942,
        'n2-standard-8': 0.3885,
    }

    AZURE_PRICING = {
        'Standard_B1s': 0.0104,
        'Standard_B1ms': 0.0207,
        'Standard_B2s': 0.0416,
        'Standard_B2ms': 0.0832,
        'Standard_B4ms': 0.166,
        'Standard_B8ms': 0.333,
        'Standard_D2s_v5': 0.096,
        'Standard_D4s_v5': 0.192,
        'Standard_D8s_v5': 0.384,
        'Standard_D16s_v5': 0.768,
        'Standard_D32s_v5': 1.536,
        'Standard_E2s_v5': 0.126,
        'Standard_E4s_v5': 0.252,
        'Standard_E8s_v5': 0.504,
    }

    # Storage pricing (per GB/month)
    STORAGE_PRICING = {
        'aws': {
            'gp3': 0.08,
            'gp2': 0.10,
            'io1': 0.125,
        },
        'gcp': {
            'pd-standard': 0.04,
            'pd-ssd': 0.17,
            'pd-balanced': 0.10,
        },
        'azure': {
            'Standard_LRS': 0.05,
            'Premium_LRS': 0.15,
            'StandardSSD_LRS': 0.075,
        }
    }

    def __init__(self, analysis_data: Dict[str, Any]):
        self.data = analysis_data
        self.specs = self._extract_specs()

    def _extract_specs(self) -> VMSpecs:
        """Extract VM specs from analysis data"""
        resources = self.data.get('processes', {}).get('resource_usage', {})
        cpu = resources.get('cpu', {})
        memory = resources.get('memory', {})
        disk = resources.get('disk', {})

        vcpus = cpu.get('count', 2)
        memory_bytes = memory.get('total', 4 * 1024 * 1024 * 1024)
        memory_gb = memory_bytes / (1024 ** 3)

        # Calculate total used storage
        storage_bytes = 0
        for mount, usage in disk.items():
            if mount == '/' or mount.startswith('/home') or mount.startswith('/var'):
                storage_bytes += usage.get('used', 0)

        storage_gb = max(20, int((storage_bytes / (1024 ** 3)) * 1.5))

        return VMSpecs(
            vcpus=vcpus,
            memory_gb=memory_gb,
            storage_gb=storage_gb
        )

    def estimate_all(self, regions: Dict[str, str] = None) -> Dict[str, CostEstimate]:
        """Estimate costs for all providers"""
        default_regions = {
            'aws': 'us-east-1',
            'gcp': 'us-central1',
            'azure': 'eastus'
        }
        regions = regions or default_regions

        estimates = {}

        estimates['aws'] = self.estimate_aws(regions.get('aws', 'us-east-1'))
        estimates['gcp'] = self.estimate_gcp(regions.get('gcp', 'us-central1'))
        estimates['azure'] = self.estimate_azure(regions.get('azure', 'eastus'))

        return estimates

    def estimate_aws(self, region: str = 'us-east-1') -> CostEstimate:
        """Estimate AWS EC2 costs"""
        instance_type = self._get_aws_instance_type()
        hourly = self.AWS_PRICING.get(instance_type, 0.0416)

        # Try to get live pricing
        live_price = self._fetch_aws_price(instance_type, region)
        if live_price:
            hourly = live_price

        # Add storage cost
        storage_monthly = self.specs.storage_gb * self.STORAGE_PRICING['aws']['gp3']

        monthly = (hourly * 730) + storage_monthly  # 730 hours/month avg
        annual = monthly * 12

        return CostEstimate(
            provider='AWS',
            instance_type=instance_type,
            region=region,
            hourly_cost=hourly,
            monthly_cost=monthly,
            annual_cost=annual,
            details={
                'compute_monthly': round(hourly * 730, 2),
                'storage_monthly': round(storage_monthly, 2),
                'storage_gb': self.specs.storage_gb,
                'storage_type': 'gp3',
                'hours_per_month': 730,
                'pricing_source': 'live' if live_price else 'estimated'
            }
        )

    def estimate_gcp(self, region: str = 'us-central1') -> CostEstimate:
        """Estimate GCP Compute Engine costs"""
        machine_type = self._get_gcp_machine_type()
        hourly = self.GCP_PRICING.get(machine_type, 0.0336)

        # Try to get live pricing
        live_price = self._fetch_gcp_price(machine_type, region)
        if live_price:
            hourly = live_price

        # Add storage cost
        storage_monthly = self.specs.storage_gb * self.STORAGE_PRICING['gcp']['pd-ssd']

        monthly = (hourly * 730) + storage_monthly
        annual = monthly * 12

        # GCP offers sustained use discounts (approx 30% for full month)
        sustained_discount = 0.70  # 30% discount
        monthly_with_discount = (hourly * 730 * sustained_discount) + storage_monthly
        annual_with_discount = monthly_with_discount * 12

        return CostEstimate(
            provider='GCP',
            instance_type=machine_type,
            region=region,
            hourly_cost=hourly,
            monthly_cost=monthly_with_discount,
            annual_cost=annual_with_discount,
            details={
                'compute_monthly': round(hourly * 730, 2),
                'compute_with_sud': round(hourly * 730 * sustained_discount, 2),
                'storage_monthly': round(storage_monthly, 2),
                'storage_gb': self.specs.storage_gb,
                'storage_type': 'pd-ssd',
                'sustained_use_discount': '30%',
                'pricing_source': 'live' if live_price else 'estimated'
            }
        )

    def estimate_azure(self, region: str = 'eastus') -> CostEstimate:
        """Estimate Azure VM costs"""
        vm_size = self._get_azure_vm_size()
        hourly = self.AZURE_PRICING.get(vm_size, 0.0416)

        # Try to get live pricing
        live_price = self._fetch_azure_price(vm_size, region)
        if live_price:
            hourly = live_price

        # Add storage cost
        storage_monthly = self.specs.storage_gb * self.STORAGE_PRICING['azure']['Premium_LRS']

        monthly = (hourly * 730) + storage_monthly
        annual = monthly * 12

        return CostEstimate(
            provider='Azure',
            instance_type=vm_size,
            region=region,
            hourly_cost=hourly,
            monthly_cost=monthly,
            annual_cost=annual,
            details={
                'compute_monthly': round(hourly * 730, 2),
                'storage_monthly': round(storage_monthly, 2),
                'storage_gb': self.specs.storage_gb,
                'storage_type': 'Premium_LRS',
                'pricing_source': 'live' if live_price else 'estimated'
            }
        )

    def _get_aws_instance_type(self) -> str:
        """Get recommended AWS instance type"""
        types = [
            (1, 1, 't3.micro'),
            (2, 2, 't3.small'),
            (2, 4, 't3.medium'),
            (2, 8, 't3.large'),
            (4, 16, 't3.xlarge'),
            (8, 32, 't3.2xlarge'),
            (4, 32, 'r6i.xlarge'),
            (8, 64, 'r6i.2xlarge'),
            (16, 64, 'm6i.4xlarge'),
            (32, 128, 'm6i.8xlarge'),
        ]

        for vcpus, mem, itype in types:
            if vcpus >= self.specs.vcpus and mem >= self.specs.memory_gb:
                return itype
        return 't3.medium'

    def _get_gcp_machine_type(self) -> str:
        """Get recommended GCP machine type"""
        types = [
            (1, 1, 'e2-micro'),
            (2, 2, 'e2-small'),
            (2, 4, 'e2-medium'),
            (2, 8, 'e2-standard-2'),
            (4, 16, 'e2-standard-4'),
            (8, 32, 'e2-standard-8'),
            (16, 64, 'e2-standard-16'),
            (32, 128, 'e2-standard-32'),
            (4, 32, 'e2-highmem-4'),
            (8, 64, 'e2-highmem-8'),
        ]

        for vcpus, mem, mtype in types:
            if vcpus >= self.specs.vcpus and mem >= self.specs.memory_gb:
                return mtype
        return 'e2-medium'

    def _get_azure_vm_size(self) -> str:
        """Get recommended Azure VM size"""
        sizes = [
            (1, 1, 'Standard_B1s'),
            (1, 2, 'Standard_B1ms'),
            (2, 4, 'Standard_B2s'),
            (2, 8, 'Standard_B2ms'),
            (4, 16, 'Standard_B4ms'),
            (8, 32, 'Standard_B8ms'),
            (2, 8, 'Standard_D2s_v5'),
            (4, 16, 'Standard_D4s_v5'),
            (8, 32, 'Standard_D8s_v5'),
            (16, 64, 'Standard_D16s_v5'),
            (4, 32, 'Standard_E4s_v5'),
        ]

        for vcpus, mem, size in sizes:
            if vcpus >= self.specs.vcpus and mem >= self.specs.memory_gb:
                return size
        return 'Standard_B2s'

    def _fetch_aws_price(self, instance_type: str, region: str) -> Optional[float]:
        """Fetch live AWS pricing using the pricing API"""
        if not REQUESTS_AVAILABLE:
            return None

        try:
            # AWS Pricing API endpoint for EC2
            # Note: This requires AWS credentials or use public pricing files
            url = f"https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/{region}/index.json"
            # This is a large file, so we'll use the static pricing instead
            # In production, you'd want to cache this or use the boto3 pricing API
            return None
        except Exception as e:
            logger.debug(f"Could not fetch AWS pricing: {e}")
            return None

    def _fetch_gcp_price(self, machine_type: str, region: str) -> Optional[float]:
        """Fetch live GCP pricing"""
        if not REQUESTS_AVAILABLE:
            return None

        try:
            # GCP Cloud Billing Catalog API
            # Requires authentication, so using static pricing
            return None
        except Exception as e:
            logger.debug(f"Could not fetch GCP pricing: {e}")
            return None

    def _fetch_azure_price(self, vm_size: str, region: str) -> Optional[float]:
        """Fetch live Azure pricing using the Retail Prices API (free, no auth required)"""
        if not REQUESTS_AVAILABLE:
            return None

        try:
            # Azure Retail Prices API - free and no authentication required
            url = "https://prices.azure.com/api/retail/prices"
            params = {
                "$filter": f"serviceName eq 'Virtual Machines' and armSkuName eq '{vm_size}' and armRegionName eq '{region}' and priceType eq 'Consumption'",
                "currencyCode": "USD"
            }

            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            items = data.get('Items', [])

            # Find Linux pricing
            for item in items:
                if 'Linux' in item.get('productName', '') and item.get('type') == 'Consumption':
                    return item.get('retailPrice', 0)

            return None
        except Exception as e:
            logger.debug(f"Could not fetch Azure pricing: {e}")
            return None

    def generate_comparison_table(self, estimates: Dict[str, CostEstimate]) -> str:
        """Generate a markdown comparison table"""
        table = """
## Cloud Cost Comparison

| Provider | Instance Type | Monthly Cost | Annual Cost | Details |
|----------|--------------|--------------|-------------|---------|
"""
        for provider, estimate in estimates.items():
            details = estimate.details or {}
            compute = details.get('compute_monthly', 'N/A')
            storage = details.get('storage_monthly', 'N/A')
            detail_str = f"Compute: ${compute}, Storage: ${storage}"

            table += f"| {estimate.provider} | {estimate.instance_type} | ${estimate.monthly_cost:,.2f} | ${estimate.annual_cost:,.2f} | {detail_str} |\n"

        # Add notes
        table += """
### Notes

- Prices are estimates based on on-demand pricing
- GCP includes ~30% sustained use discount for full-month usage
- Storage costs assume SSD/Premium storage
- Actual costs may vary based on:
  - Reserved instances / Committed use discounts (30-70% savings)
  - Spot/Preemptible instances (60-90% savings)
  - Data transfer costs
  - Additional services (load balancers, IPs, etc.)

### Recommendations

"""
        # Find cheapest
        sorted_estimates = sorted(estimates.values(), key=lambda x: x.annual_cost)
        cheapest = sorted_estimates[0]

        table += f"- **Most Cost-Effective**: {cheapest.provider} ({cheapest.instance_type}) at ${cheapest.annual_cost:,.2f}/year\n"
        table += f"- Consider reserved/committed use for 30-70% additional savings\n"
        table += f"- Use spot/preemptible instances for non-critical workloads\n"

        return table

    def generate_report(self) -> Dict[str, Any]:
        """Generate a full cost report"""
        estimates = self.estimate_all()

        report = {
            'specs': {
                'vcpus': self.specs.vcpus,
                'memory_gb': round(self.specs.memory_gb, 1),
                'storage_gb': self.specs.storage_gb
            },
            'estimates': {k: v.to_dict() for k, v in estimates.items()},
            'comparison': self.generate_comparison_table(estimates),
            'cheapest': min(estimates.values(), key=lambda x: x.annual_cost).to_dict()
        }

        return report
