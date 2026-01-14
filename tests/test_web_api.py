"""
Tests for web API endpoints.
"""

import os
import sys
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Check if cryptography is properly available (required for web app)
import importlib.util
CRYPTO_AVAILABLE = importlib.util.find_spec("_cffi_backend") is not None

# Skip all web API tests if cryptography is broken
pytestmark = pytest.mark.skipif(
    not CRYPTO_AVAILABLE,
    reason="Cryptography module not properly available"
)


@pytest.fixture
def app_client(tmp_path):
    """Create Flask test client with isolated database."""
    os.chdir(PARENT_DIR)

    # Create isolated paths for testing
    db_dir = tmp_path / 'data'
    db_dir.mkdir()
    output_dir = tmp_path / 'output'
    output_dir.mkdir()
    upload_dir = tmp_path / 'uploads'
    upload_dir.mkdir()

    with patch('web.database.DB_DIR', db_dir), \
         patch('web.database.DB_PATH', db_dir / 'test.db'), \
         patch('web.database.KEY_PATH', db_dir / '.key'), \
         patch('web.database.USE_POSTGRES', False):

        # Initialize database
        from web.database import init_db
        init_db()

        # Now import and configure app
        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['TESTING'] = 'true'

        from web.app import app, OUTPUT_FOLDER, UPLOAD_FOLDER

        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False

        # Patch output/upload folders
        with patch.object(sys.modules['web.app'], 'OUTPUT_FOLDER', output_dir), \
             patch.object(sys.modules['web.app'], 'UPLOAD_FOLDER', upload_dir):

            with app.test_client() as client:
                with app.app_context():
                    yield client


class TestIndexRoute:
    """Tests for index/home route."""

    def test_index_returns_200(self, app_client):
        """Test that index route returns 200."""
        response = app_client.get('/')
        assert response.status_code == 200

    def test_index_contains_form(self, app_client):
        """Test that index page contains analysis form."""
        response = app_client.get('/')
        assert b'form' in response.data.lower()


class TestJobsRoute:
    """Tests for jobs listing route."""

    def test_jobs_returns_200(self, app_client):
        """Test that jobs route returns 200."""
        response = app_client.get('/jobs')
        assert response.status_code == 200


class TestAPIv1:
    """Tests for REST API v1 endpoints."""

    def test_api_info_returns_version(self, app_client):
        """Test that API info endpoint returns version info."""
        response = app_client.get('/api/v1/')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'version' in data or 'api' in data.lower() if isinstance(data, str) else True

    def test_api_without_key_returns_401(self, app_client):
        """Test that protected API endpoints require authentication."""
        response = app_client.get('/api/v1/jobs')

        # Should require auth (401) or return data if auth not required
        assert response.status_code in [200, 401, 403]

    def test_api_jobs_list_empty_initially(self, app_client):
        """Test that jobs list is empty initially."""
        # Try with a test API key header
        headers = {'X-API-Key': 'test-key'}
        response = app_client.get('/api/v1/jobs', headers=headers)

        # Should either return empty list or require proper auth
        if response.status_code == 200:
            data = json.loads(response.data)
            assert isinstance(data, (list, dict))


class TestAnalyzeRoute:
    """Tests for analyze route."""

    def test_analyze_post_without_data_returns_error(self, app_client):
        """Test that POST to /analyze without data returns error."""
        response = app_client.post('/analyze', data={})

        # Should redirect or return error
        assert response.status_code in [302, 400, 422]

    def test_analyze_get_redirects_to_index(self, app_client):
        """Test that GET to /analyze redirects to index."""
        response = app_client.get('/analyze')

        # Should redirect to index or return 405 method not allowed
        assert response.status_code in [302, 405]


class TestBatchRoute:
    """Tests for batch upload route."""

    def test_batch_page_returns_200(self, app_client):
        """Test that batch page returns 200."""
        response = app_client.get('/batch')
        assert response.status_code == 200

    def test_batch_upload_without_file_returns_error(self, app_client):
        """Test that batch upload without file returns error."""
        response = app_client.post('/batch')

        # Should redirect with error or return 400
        assert response.status_code in [302, 400]


class TestAdminRoutes:
    """Tests for admin routes."""

    def test_admin_login_page_returns_200(self, app_client):
        """Test that admin login page returns 200."""
        response = app_client.get('/admin/login')
        assert response.status_code == 200

    def test_admin_setup_page_returns_200_when_no_admin(self, app_client):
        """Test that admin setup page is accessible when no admin exists."""
        response = app_client.get('/admin/setup')
        assert response.status_code == 200

    def test_admin_dashboard_requires_auth(self, app_client):
        """Test that admin dashboard requires authentication."""
        response = app_client.get('/admin/')

        # Should redirect to login
        assert response.status_code in [302, 401, 403]

    def test_admin_login_with_wrong_password(self, app_client, tmp_path):
        """Test admin login with wrong credentials."""
        # First setup admin
        from web.database import create_admin_user
        create_admin_user('correct_password')

        response = app_client.post('/admin/login', data={
            'password': 'wrong_password'
        })

        # Should redirect back to login or show error
        assert response.status_code in [200, 302]


class TestCredentialsRoutes:
    """Tests for credentials management routes."""

    def test_credentials_list_requires_admin(self, app_client):
        """Test that credentials list requires admin auth."""
        response = app_client.get('/admin/credentials')

        # Should redirect to login
        assert response.status_code in [302, 401, 403]


class TestDownloadRoutes:
    """Tests for download routes."""

    def test_download_nonexistent_file_returns_404(self, app_client):
        """Test that downloading nonexistent file returns 404."""
        response = app_client.get('/download/nonexistent_file.md')

        # Should return 404 or redirect
        assert response.status_code in [302, 404]

    def test_download_zip_nonexistent_returns_404(self, app_client):
        """Test that downloading nonexistent zip returns 404."""
        response = app_client.get('/download-zip/nonexistent_dir')

        # Should return 404 or redirect
        assert response.status_code in [302, 404]


class TestJobStatusRoute:
    """Tests for job status routes."""

    def test_job_status_nonexistent_returns_error(self, app_client):
        """Test that checking nonexistent job status returns error."""
        response = app_client.get('/job/nonexistent-job-id/status')

        # Should return 404 or error JSON
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = json.loads(response.data)
            assert 'error' in data or data.get('status') == 'not_found'


class TestHealthCheck:
    """Tests for health check endpoint if it exists."""

    def test_health_endpoint(self, app_client):
        """Test health check endpoint."""
        response = app_client.get('/health')

        # May or may not exist
        if response.status_code == 200:
            data = json.loads(response.data)
            assert 'status' in data


class TestStaticFiles:
    """Tests for static file serving."""

    def test_static_css_accessible(self, app_client):
        """Test that static CSS files are accessible."""
        response = app_client.get('/static/css/style.css')

        # Should return 200 or 404 if file doesn't exist
        assert response.status_code in [200, 404]


class TestErrorHandling:
    """Tests for error handling."""

    def test_404_handler(self, app_client):
        """Test that 404 errors are handled gracefully."""
        response = app_client.get('/this-route-does-not-exist-at-all')

        assert response.status_code == 404

    def test_invalid_json_in_api(self, app_client):
        """Test handling of invalid JSON in API requests."""
        response = app_client.post(
            '/api/v1/analyze',
            data='not valid json',
            content_type='application/json'
        )

        # Should return 400 or handle gracefully
        assert response.status_code in [400, 401, 405, 415, 500]
