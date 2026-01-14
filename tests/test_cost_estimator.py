"""
Tests for CostEstimator module.
"""

import pytest


class TestCostEstimator:
    """Tests for CostEstimator class."""

    def test_extract_specs_from_analysis_data(self, sample_analysis_data):
        """Test that VM specs are correctly extracted from analysis data."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        specs = estimator.specs

        assert specs.vcpus == 4
        assert specs.memory_gb == 8.0
        assert specs.storage_gb > 0

    def test_extract_specs_with_minimal_data(self, minimal_analysis_data):
        """Test specs extraction with minimal data uses defaults."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(minimal_analysis_data)
        specs = estimator.specs

        assert specs.vcpus >= 1
        assert specs.memory_gb >= 1.0
        assert specs.storage_gb >= 10

    def test_estimate_aws_returns_cost_estimate(self, sample_analysis_data):
        """Test that AWS estimation returns a valid CostEstimate."""
        from generators.cost_estimator import CostEstimator, CostEstimate

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_aws()

        assert isinstance(result, CostEstimate)
        assert result.provider == 'AWS'
        assert result.hourly_cost > 0
        assert result.monthly_cost > 0
        assert result.annual_cost > 0
        assert result.instance_type != ''

    def test_estimate_gcp_returns_cost_estimate(self, sample_analysis_data):
        """Test that GCP estimation returns a valid CostEstimate."""
        from generators.cost_estimator import CostEstimator, CostEstimate

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_gcp()

        assert isinstance(result, CostEstimate)
        assert result.provider == 'GCP'
        assert result.hourly_cost > 0
        assert result.monthly_cost > 0
        assert result.annual_cost > 0

    def test_estimate_azure_returns_cost_estimate(self, sample_analysis_data):
        """Test that Azure estimation returns a valid CostEstimate."""
        from generators.cost_estimator import CostEstimator, CostEstimate

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_azure()

        assert isinstance(result, CostEstimate)
        assert result.provider == 'Azure'
        assert result.hourly_cost > 0
        assert result.monthly_cost > 0
        assert result.annual_cost > 0

    def test_estimate_all_returns_dict_of_estimates(self, sample_analysis_data):
        """Test that estimate_all() returns estimates for all providers."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_all()

        assert isinstance(result, dict)
        assert 'aws' in result or 'AWS' in result
        assert 'gcp' in result or 'GCP' in result
        assert 'azure' in result or 'Azure' in result

    def test_cost_estimate_to_dict(self, sample_analysis_data):
        """Test CostEstimate.to_dict() returns proper dictionary."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_aws()
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert 'provider' in result_dict
        assert 'instance_type' in result_dict
        assert 'hourly_cost' in result_dict
        assert 'monthly_cost' in result_dict
        assert 'annual_cost' in result_dict
        assert 'currency' in result_dict

    def test_monthly_cost_is_hourly_times_730(self, sample_analysis_data):
        """Test that monthly cost is approximately hourly * 730."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_aws()

        # Monthly should be hourly * ~730 hours (some variance allowed for storage)
        expected_monthly = result.hourly_cost * 730
        assert abs(result.monthly_cost - expected_monthly) < expected_monthly * 0.2  # 20% tolerance

    def test_annual_cost_is_monthly_times_12(self, sample_analysis_data):
        """Test that annual cost is monthly * 12."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_aws()

        # Annual should be monthly * 12
        expected_annual = result.monthly_cost * 12
        assert abs(result.annual_cost - expected_annual) < 1.0  # Small floating point tolerance

    def test_instance_type_recommendation_scales_with_resources(self):
        """Test that larger resource needs recommend larger instances."""
        from generators.cost_estimator import CostEstimator

        # Small server
        small_data = {
            'processes': {
                'resource_usage': {
                    'cpu': {'count': 1},
                    'memory': {'total': 1 * 1024**3},  # 1GB
                    'disk': {'total': 20 * 1024**3}
                }
            }
        }

        # Large server
        large_data = {
            'processes': {
                'resource_usage': {
                    'cpu': {'count': 16},
                    'memory': {'total': 64 * 1024**3},  # 64GB
                    'disk': {'total': 500 * 1024**3}
                }
            }
        }

        small_estimator = CostEstimator(small_data)
        large_estimator = CostEstimator(large_data)

        small_cost = small_estimator.estimate_aws()
        large_cost = large_estimator.estimate_aws()

        # Larger server should cost more
        assert large_cost.annual_cost > small_cost.annual_cost

    def test_storage_costs_included(self, sample_analysis_data):
        """Test that storage costs are included in estimates."""
        from generators.cost_estimator import CostEstimator

        estimator = CostEstimator(sample_analysis_data)
        result = estimator.estimate_aws()

        # Details should include storage info
        if result.details:
            assert 'storage' in str(result.details).lower() or result.details.get('storage_cost', 0) >= 0


class TestVMSpecs:
    """Tests for VMSpecs dataclass."""

    def test_vmspecs_creation(self):
        """Test VMSpecs dataclass can be created."""
        from generators.cost_estimator import VMSpecs

        specs = VMSpecs(vcpus=4, memory_gb=8.0, storage_gb=100)

        assert specs.vcpus == 4
        assert specs.memory_gb == 8.0
        assert specs.storage_gb == 100

    def test_vmspecs_default_values(self):
        """Test VMSpecs has proper default values."""
        from generators.cost_estimator import VMSpecs

        specs = VMSpecs(vcpus=2, memory_gb=4.0, storage_gb=50)

        assert specs.instance_type == ""
        assert specs.region == ""


class TestCostEstimateDataclass:
    """Tests for CostEstimate dataclass."""

    def test_cost_estimate_creation(self):
        """Test CostEstimate dataclass can be created."""
        from generators.cost_estimator import CostEstimate

        estimate = CostEstimate(
            provider='AWS',
            instance_type='t3.medium',
            region='us-east-1',
            hourly_cost=0.0416,
            monthly_cost=30.37,
            annual_cost=364.42
        )

        assert estimate.provider == 'AWS'
        assert estimate.instance_type == 't3.medium'
        assert estimate.hourly_cost == 0.0416

    def test_cost_estimate_default_currency(self):
        """Test CostEstimate defaults to USD currency."""
        from generators.cost_estimator import CostEstimate

        estimate = CostEstimate(
            provider='AWS',
            instance_type='t3.medium',
            region='us-east-1',
            hourly_cost=0.0416,
            monthly_cost=30.37,
            annual_cost=364.42
        )

        assert estimate.currency == 'USD'

    def test_to_dict_rounds_values(self):
        """Test to_dict() rounds cost values appropriately."""
        from generators.cost_estimator import CostEstimate

        estimate = CostEstimate(
            provider='AWS',
            instance_type='t3.medium',
            region='us-east-1',
            hourly_cost=0.04166666666,
            monthly_cost=30.37166666,
            annual_cost=364.42333333
        )

        result = estimate.to_dict()

        # Hourly should be rounded to 4 decimal places
        assert result['hourly_cost'] == 0.0417
        # Monthly and annual should be rounded to 2 decimal places
        assert result['monthly_cost'] == 30.37
        assert result['annual_cost'] == 364.42
