"""
GitLab Connector
Scans GitLab repositories to infer system purpose and configurations
"""

import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available")


class GitLabConnector:
    """Connects to GitLab API to scan repositories"""

    def __init__(self, url: str, token: str):
        self.base_url = url.rstrip('/')
        self.token = token
        self.api_url = f"{self.base_url}/api/v4"
        self.headers = {
            'PRIVATE-TOKEN': token,
            'Content-Type': 'application/json'
        }
        self.data = {
            'projects': [],
            'pipelines': [],
            'deployments': [],
            'related_configs': []
        }

    def scan_repos(self) -> Dict[str, Any]:
        """Scan GitLab repositories for relevant information"""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library required for GitLab scanning")
            return {}

        if not self.token:
            logger.warning("GitLab token not provided")
            return {}

        try:
            self._get_projects()
            self._scan_project_configs()
            self._get_pipelines()
            self._get_deployments()
        except Exception as e:
            logger.error(f"Error scanning GitLab: {e}")

        return self.data

    def _api_get(self, endpoint: str, params: Dict = None) -> Optional[Any]:
        """Make GET request to GitLab API"""
        try:
            response = requests.get(
                f"{self.api_url}/{endpoint}",
                headers=self.headers,
                params=params or {},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"GitLab API error for {endpoint}: {e}")
            return None

    def _get_projects(self) -> List[Dict]:
        """Get list of accessible projects"""
        projects = []
        page = 1

        while True:
            result = self._api_get('projects', {
                'per_page': 100,
                'page': page,
                'membership': True
            })

            if not result:
                break

            for project in result:
                projects.append({
                    'id': project['id'],
                    'name': project['name'],
                    'path': project['path_with_namespace'],
                    'description': project.get('description', ''),
                    'default_branch': project.get('default_branch', 'main'),
                    'web_url': project.get('web_url', ''),
                    'last_activity': project.get('last_activity_at', ''),
                    'topics': project.get('topics', [])
                })

            if len(result) < 100:
                break
            page += 1

        self.data['projects'] = projects
        return projects

    def _scan_project_configs(self) -> List[Dict]:
        """Scan projects for configuration files"""
        configs = []
        config_files = [
            '.gitlab-ci.yml',
            'docker-compose.yml',
            'docker-compose.yaml',
            'Dockerfile',
            'kubernetes/',
            'k8s/',
            'terraform/',
            'ansible/',
            '.env.example',
            'config/'
        ]

        for project in self.data['projects'][:20]:  # Limit to first 20 projects
            project_id = project['id']

            for config_file in config_files:
                try:
                    # Try to get file content
                    result = self._api_get(
                        f"projects/{project_id}/repository/files/{config_file.replace('/', '%2F')}",
                        {'ref': project['default_branch']}
                    )

                    if result:
                        configs.append({
                            'project': project['path'],
                            'file': config_file,
                            'exists': True,
                            'size': result.get('size', 0)
                        })
                except Exception:
                    pass

            # Check for tree structure
            tree = self._api_get(f"projects/{project_id}/repository/tree", {
                'ref': project['default_branch'],
                'per_page': 100
            })

            if tree:
                for item in tree:
                    name = item['name'].lower()
                    if any(cf.rstrip('/') in name for cf in config_files):
                        configs.append({
                            'project': project['path'],
                            'file': item['path'],
                            'type': item['type']
                        })

        self.data['related_configs'] = configs
        return configs

    def _get_pipelines(self) -> List[Dict]:
        """Get recent pipeline information"""
        pipelines = []

        for project in self.data['projects'][:10]:
            project_id = project['id']

            result = self._api_get(f"projects/{project_id}/pipelines", {
                'per_page': 5,
                'order_by': 'updated_at',
                'sort': 'desc'
            })

            if result:
                for pipeline in result:
                    pipelines.append({
                        'project': project['path'],
                        'id': pipeline['id'],
                        'status': pipeline['status'],
                        'ref': pipeline['ref'],
                        'created_at': pipeline.get('created_at', ''),
                        'updated_at': pipeline.get('updated_at', '')
                    })

        self.data['pipelines'] = pipelines
        return pipelines

    def _get_deployments(self) -> List[Dict]:
        """Get deployment information"""
        deployments = []

        for project in self.data['projects'][:10]:
            project_id = project['id']

            # Get environments
            envs = self._api_get(f"projects/{project_id}/environments", {
                'per_page': 10
            })

            if envs:
                for env in envs:
                    deployments.append({
                        'project': project['path'],
                        'environment': env['name'],
                        'state': env.get('state', ''),
                        'external_url': env.get('external_url', '')
                    })

        self.data['deployments'] = deployments
        return deployments

    def get_ci_config(self, project_id: int) -> Optional[str]:
        """Get CI/CD configuration for a project"""
        result = self._api_get(
            f"projects/{project_id}/repository/files/.gitlab-ci.yml/raw",
            {'ref': 'main'}
        )
        return result

    def search_code(self, query: str) -> List[Dict]:
        """Search for code across projects"""
        results = []

        search_result = self._api_get('search', {
            'scope': 'blobs',
            'search': query,
            'per_page': 20
        })

        if search_result:
            for item in search_result:
                results.append({
                    'project': item.get('project_id'),
                    'path': item.get('path'),
                    'filename': item.get('filename'),
                    'ref': item.get('ref')
                })

        return results

    def find_related_projects(self, hostname: str) -> List[Dict]:
        """Find projects that might be related to a specific hostname"""
        related = []

        # Search for hostname in code
        search_results = self.search_code(hostname)
        related.extend(search_results)

        # Search for hostname in project descriptions
        for project in self.data['projects']:
            desc = project.get('description', '').lower()
            if hostname.lower() in desc:
                related.append({
                    'project': project['path'],
                    'match_type': 'description'
                })

        return related
