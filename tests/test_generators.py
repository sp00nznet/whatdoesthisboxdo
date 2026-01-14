"""
Tests for IaC generator modules.
"""

import os
import json
import pytest
from pathlib import Path


class TestTerraformGenerator:
    """Tests for TerraformGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'terraform')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_required_files(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates all required Terraform files."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'terraform')
        gen.generate(output_path)

        expected_files = ['main.tf', 'variables.tf', 'terraform.tfvars.example', 'outputs.tf', 'provider.tf']
        for filename in expected_files:
            assert os.path.isfile(os.path.join(output_path, filename)), f"Missing {filename}"

    def test_main_tf_contains_vm_resource(self, sample_analysis_data, temp_output_dir):
        """Test that main.tf contains VM resource definition."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'terraform')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'main.tf')) as f:
            content = f.read()

        assert 'resource "vsphere_virtual_machine"' in content
        assert 'test_server' in content or 'test-server' in content

    def test_variables_contain_vm_specs(self, sample_analysis_data, temp_output_dir):
        """Test that variables.tf contains VM specification variables."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'terraform')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'variables.tf')) as f:
            content = f.read()

        assert 'variable "vm_cpus"' in content
        assert 'variable "vm_memory"' in content

    def test_get_vm_specs_from_vcenter(self, sample_analysis_data):
        """Test that VM specs are extracted from vCenter data."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(sample_analysis_data)
        specs = gen._get_vm_specs()

        assert specs['num_cpus'] == 4
        assert specs['memory'] == 8192
        assert specs['disk_size'] == 100

    def test_get_vm_specs_with_minimal_data(self, minimal_analysis_data):
        """Test VM specs extraction with minimal data falls back to defaults."""
        from generators.terraform_generator import TerraformGenerator

        gen = TerraformGenerator(minimal_analysis_data)
        specs = gen._get_vm_specs()

        assert specs['num_cpus'] >= 1
        assert specs['memory'] >= 1024
        assert specs['disk_size'] >= 10


class TestAWSGenerator:
    """Tests for AWSGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.aws_generator import AWSGenerator

        gen = AWSGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'aws')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_required_files(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates all required AWS Terraform files."""
        from generators.aws_generator import AWSGenerator

        gen = AWSGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'aws')
        gen.generate(output_path)

        expected_files = ['main.tf', 'variables.tf', 'outputs.tf']
        for filename in expected_files:
            assert os.path.isfile(os.path.join(output_path, filename)), f"Missing {filename}"

    def test_main_tf_contains_ec2_instance(self, sample_analysis_data, temp_output_dir):
        """Test that main.tf contains EC2 instance resource."""
        from generators.aws_generator import AWSGenerator

        gen = AWSGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'aws')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'main.tf')) as f:
            content = f.read()

        assert 'resource "aws_instance"' in content
        assert 'aws_security_group' in content

    def test_security_group_has_listening_ports(self, sample_analysis_data, temp_output_dir):
        """Test that security group includes listening ports."""
        from generators.aws_generator import AWSGenerator

        gen = AWSGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'aws')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'main.tf')) as f:
            content = f.read()

        # Check for common ports from sample data
        assert '80' in content or 'http' in content.lower()
        assert '443' in content or 'https' in content.lower()


class TestGCPGenerator:
    """Tests for GCPGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.gcp_generator import GCPGenerator

        gen = GCPGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'gcp')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_required_files(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates all required GCP Terraform files."""
        from generators.gcp_generator import GCPGenerator

        gen = GCPGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'gcp')
        gen.generate(output_path)

        expected_files = ['main.tf', 'variables.tf', 'outputs.tf']
        for filename in expected_files:
            assert os.path.isfile(os.path.join(output_path, filename)), f"Missing {filename}"

    def test_main_tf_contains_compute_instance(self, sample_analysis_data, temp_output_dir):
        """Test that main.tf contains GCP compute instance resource."""
        from generators.gcp_generator import GCPGenerator

        gen = GCPGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'gcp')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'main.tf')) as f:
            content = f.read()

        assert 'resource "google_compute_instance"' in content


class TestAzureGenerator:
    """Tests for AzureGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.azure_generator import AzureGenerator

        gen = AzureGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'azure')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_required_files(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates all required Azure Terraform files."""
        from generators.azure_generator import AzureGenerator

        gen = AzureGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'azure')
        gen.generate(output_path)

        expected_files = ['main.tf', 'variables.tf', 'outputs.tf']
        for filename in expected_files:
            assert os.path.isfile(os.path.join(output_path, filename)), f"Missing {filename}"

    def test_main_tf_contains_azure_vm(self, sample_analysis_data, temp_output_dir):
        """Test that main.tf contains Azure VM resource."""
        from generators.azure_generator import AzureGenerator

        gen = AzureGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'azure')
        gen.generate(output_path)

        with open(os.path.join(output_path, 'main.tf')) as f:
            content = f.read()

        assert 'azurerm_linux_virtual_machine' in content or 'azurerm_virtual_machine' in content


class TestAnsibleGenerator:
    """Tests for AnsibleGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.ansible_generator import AnsibleGenerator

        gen = AnsibleGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_playbook(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates playbook files."""
        from generators.ansible_generator import AnsibleGenerator

        gen = AnsibleGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible')
        gen.generate(output_path)

        # Check for playbook or site.yml
        yaml_files = list(Path(output_path).glob('*.yml')) + list(Path(output_path).glob('*.yaml'))
        assert len(yaml_files) > 0, "No YAML playbook files found"

    def test_playbook_contains_package_installation(self, sample_analysis_data, temp_output_dir):
        """Test that playbook includes package installation tasks."""
        from generators.ansible_generator import AnsibleGenerator

        gen = AnsibleGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible')
        gen.generate(output_path)

        # Read all yaml files and check for package module
        found_packages = False
        for yaml_file in Path(output_path).rglob('*.yml'):
            content = yaml_file.read_text()
            if 'apt:' in content or 'package:' in content or 'yum:' in content:
                found_packages = True
                break

        assert found_packages, "No package installation tasks found"


class TestAnsibleFullGenerator:
    """Tests for AnsibleFullGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.ansible_full_generator import AnsibleFullGenerator

        gen = AnsibleFullGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible-full')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_roles_structure(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates Ansible roles directory structure."""
        from generators.ansible_full_generator import AnsibleFullGenerator

        gen = AnsibleFullGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible-full')
        gen.generate(output_path)

        # Check for roles directory
        roles_dir = Path(output_path) / 'roles'
        assert roles_dir.is_dir() or any(Path(output_path).rglob('*/tasks/main.yml')), \
            "No roles structure found"

    def test_generate_creates_inventory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates inventory file."""
        from generators.ansible_full_generator import AnsibleFullGenerator

        gen = AnsibleFullGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'ansible-full')
        gen.generate(output_path)

        inventory_files = list(Path(output_path).glob('inventory*')) + \
                          list(Path(output_path).glob('hosts*'))
        assert len(inventory_files) > 0 or any(Path(output_path).rglob('inventory*')), \
            "No inventory file found"


class TestDocumentationGenerator:
    """Tests for DocumentationGenerator class."""

    def test_generate_returns_markdown(self, sample_analysis_data):
        """Test that generate() returns markdown content."""
        from generators.doc_generator import DocumentationGenerator

        gen = DocumentationGenerator()
        result = gen.generate(sample_analysis_data)

        assert isinstance(result, str)
        assert len(result) > 0
        assert '#' in result  # Should contain markdown headers

    def test_generate_includes_hostname(self, sample_analysis_data):
        """Test that generated markdown includes hostname."""
        from generators.doc_generator import DocumentationGenerator

        gen = DocumentationGenerator()
        result = gen.generate(sample_analysis_data)

        assert 'test-server' in result

    def test_generate_includes_services(self, sample_analysis_data):
        """Test that generated markdown includes services."""
        from generators.doc_generator import DocumentationGenerator

        gen = DocumentationGenerator()
        result = gen.generate(sample_analysis_data)

        # Should mention at least one of the services
        assert any(svc in result.lower() for svc in ['nginx', 'postgresql', 'docker'])

    def test_generate_html_returns_html(self, sample_analysis_data):
        """Test that generate_html() returns valid HTML."""
        from generators.doc_generator import DocumentationGenerator

        gen = DocumentationGenerator()
        result = gen.generate_html(sample_analysis_data)

        assert isinstance(result, str)
        assert '<html' in result.lower() or '<!doctype' in result.lower()

    def test_generate_with_minimal_data(self, minimal_analysis_data):
        """Test generation with minimal data doesn't crash."""
        from generators.doc_generator import DocumentationGenerator

        gen = DocumentationGenerator()
        result = gen.generate(minimal_analysis_data)

        assert isinstance(result, str)
        assert len(result) > 0


class TestPackerGenerator:
    """Tests for PackerGenerator class."""

    def test_generate_creates_output_directory(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates the output directory."""
        from generators.packer_generator import PackerGenerator

        gen = PackerGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'packer')
        result = gen.generate(output_path)

        assert os.path.isdir(output_path)
        assert result == output_path

    def test_generate_creates_packer_config(self, sample_analysis_data, temp_output_dir):
        """Test that generate() creates Packer configuration files."""
        from generators.packer_generator import PackerGenerator

        gen = PackerGenerator(sample_analysis_data)
        output_path = os.path.join(temp_output_dir, 'packer')
        gen.generate(output_path)

        # Check for Packer config files (could be .json or .pkr.hcl)
        config_files = list(Path(output_path).glob('*.json')) + \
                       list(Path(output_path).glob('*.pkr.hcl')) + \
                       list(Path(output_path).glob('*.pkr.json'))
        assert len(config_files) > 0, "No Packer configuration files found"
