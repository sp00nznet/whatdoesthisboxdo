"""
Pytest configuration and fixtures for whatdoesthisboxdo tests.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)


@pytest.fixture
def sample_analysis_data():
    """Provide sample analysis data for testing generators."""
    return {
        'timestamp': datetime.now().isoformat(),
        'hostname': 'test-server',
        'processes': {
            'running_processes': [
                {'name': 'nginx', 'pid': 1234, 'cpu_percent': 2.5, 'memory_percent': 1.2},
                {'name': 'python', 'pid': 5678, 'cpu_percent': 5.0, 'memory_percent': 3.5},
                {'name': 'postgres', 'pid': 9012, 'cpu_percent': 1.0, 'memory_percent': 8.0},
            ],
            'listening_ports': [
                {'port': 80, 'protocol': 'tcp', 'process': 'nginx', 'address': '0.0.0.0'},
                {'port': 443, 'protocol': 'tcp', 'process': 'nginx', 'address': '0.0.0.0'},
                {'port': 5432, 'protocol': 'tcp', 'process': 'postgres', 'address': '127.0.0.1'},
                {'port': 8000, 'protocol': 'tcp', 'process': 'python', 'address': '0.0.0.0'},
            ],
            'resource_usage': {
                'cpu': {
                    'count': 4,
                    'percent': 25.5,
                    'load_avg': [1.2, 0.8, 0.5]
                },
                'memory': {
                    'total': 8589934592,  # 8GB in bytes
                    'available': 4294967296,  # 4GB
                    'percent': 50.0,
                    'used': 4294967296
                },
                'disk': {
                    '/': {
                        'total': 107374182400,  # 100GB
                        'used': 53687091200,  # 50GB
                        'free': 53687091200,
                        'percent': 50.0
                    },
                    '/data': {
                        'total': 214748364800,  # 200GB
                        'used': 107374182400,  # 100GB
                        'free': 107374182400,
                        'percent': 50.0
                    }
                }
            },
            'services': [
                {'name': 'nginx', 'status': 'running', 'enabled': True},
                {'name': 'postgresql', 'status': 'running', 'enabled': True},
                {'name': 'docker', 'status': 'running', 'enabled': True},
            ]
        },
        'files': {
            'packages': {
                'apt': ['nginx', 'python3', 'postgresql', 'docker-ce'],
                'pip': ['flask', 'gunicorn', 'psycopg2'],
                'npm': ['pm2', 'express']
            },
            'important_dirs': [
                {'path': '/var/www/html', 'size': 1073741824},
                {'path': '/opt/app', 'size': 536870912},
            ],
            'config_files': [
                '/etc/nginx/nginx.conf',
                '/etc/postgresql/14/main/postgresql.conf',
            ],
            'mounts': [
                {'device': '/dev/sda1', 'mountpoint': '/', 'fstype': 'ext4', 'options': 'rw'},
                {'device': '/dev/sdb1', 'mountpoint': '/data', 'fstype': 'ext4', 'options': 'rw'},
            ]
        },
        'history': {
            'setup_commands': [
                {'command': 'apt update', 'user': 'root'},
                {'command': 'apt install -y nginx', 'user': 'root'},
                {'command': 'systemctl enable nginx', 'user': 'root'},
            ],
            'cron_jobs': [
                {'schedule': '0 0 * * *', 'command': '/usr/bin/backup.sh', 'user': 'root'},
            ]
        },
        'virtualization': {
            'platform': 'vcenter',
            'data': {
                'current_vm': {
                    'name': 'test-server',
                    'num_cpu': 4,
                    'memory_mb': 8192,
                    'total_disk_gb': 100,
                    'guest_id': 'ubuntu64Guest',
                    'folder': '/Datacenter/vm/Production',
                    'datastore': ['datastore1']
                }
            }
        },
        'docker': {
            'containers': [
                {
                    'name': 'web-app',
                    'image': 'myapp:latest',
                    'status': 'running',
                    'ports': ['8080:80']
                }
            ],
            'networks': ['bridge', 'app-network'],
            'volumes': ['app-data', 'logs']
        },
        'summary': {
            'purpose': 'Web application server',
            'primary_services': ['nginx', 'postgresql', 'docker'],
            'workload_type': 'web-server',
            'confidence_score': 85
        },
        'external_sources': {
            'gitlab': {'configured': False, 'connected': False, 'error': None, 'data_collected': False},
            'harbor': {'configured': False, 'connected': False, 'error': None, 'data_collected': False},
            'vcenter': {'configured': True, 'connected': True, 'error': None, 'data_collected': True},
            'proxmox': {'configured': False, 'connected': False, 'error': None, 'data_collected': False}
        }
    }


@pytest.fixture
def minimal_analysis_data():
    """Provide minimal analysis data for edge case testing."""
    return {
        'timestamp': datetime.now().isoformat(),
        'hostname': 'minimal-server',
        'processes': {
            'running_processes': [],
            'listening_ports': [],
            'resource_usage': {
                'cpu': {'count': 1, 'percent': 5.0},
                'memory': {'total': 1073741824, 'available': 536870912, 'percent': 50.0},
                'disk': {
                    '/': {'total': 10737418240, 'used': 5368709120, 'free': 5368709120, 'percent': 50.0}
                }
            }
        },
        'files': {
            'packages': {'apt': [], 'pip': [], 'npm': []},
            'important_dirs': [],
            'config_files': []
        },
        'history': {'setup_commands': [], 'cron_jobs': []},
        'virtualization': {},
        'docker': {},
        'summary': {}
    }


@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for test outputs."""
    temp_dir = tempfile.mkdtemp(prefix='wtbd_test_')
    yield temp_dir
    # Cleanup after test
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_ssh_executor():
    """Mock SSH executor for testing without actual connections."""
    with patch('connectors.ssh_executor.SSHExecutor') as mock:
        mock_instance = MagicMock()
        mock_instance.execute.return_value = ('test output', '', 0)
        mock_instance.is_connected.return_value = True
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def flask_test_client():
    """Create Flask test client for API testing."""
    # Import here to avoid circular imports
    os.chdir(PARENT_DIR)

    # Set test environment
    os.environ['TESTING'] = 'true'
    os.environ['SECRET_KEY'] = 'test-secret-key'

    from web.app import app
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def sample_credential():
    """Provide sample credential data for testing."""
    return {
        'name': 'test-server-cred',
        'hostname': 'test.example.com',
        'username': 'testuser',
        'password': 'testpass123',
        'ssh_key': None,
        'port': 22,
        'os_type': 'linux'
    }


@pytest.fixture
def mock_database(tmp_path):
    """Set up mock database for testing."""
    # Create temporary database directory
    db_dir = tmp_path / 'data'
    db_dir.mkdir()

    # Patch database paths
    with patch('web.database.DB_DIR', db_dir), \
         patch('web.database.DB_PATH', db_dir / 'test.db'), \
         patch('web.database.KEY_PATH', db_dir / '.key'), \
         patch('web.database.USE_POSTGRES', False):

        from web.database import init_db
        init_db()
        yield db_dir
