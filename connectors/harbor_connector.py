"""
Harbor Connector
Scans Harbor container registry to understand deployed applications
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available")


class HarborConnector:
    """Connects to Harbor registry API"""

    def __init__(self, url: str, username: str, password: str):
        self.base_url = url.rstrip('/')
        self.username = username
        self.password = password
        self.api_url = f"{self.base_url}/api/v2.0"
        self.session = None
        self.data = {
            'projects': [],
            'repositories': [],
            'artifacts': [],
            'scan_results': []
        }

    def _get_session(self) -> requests.Session:
        """Get authenticated session"""
        if not self.session:
            self.session = requests.Session()
            self.session.auth = (self.username, self.password)
            self.session.headers.update({
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        return self.session

    def _api_get(self, endpoint: str, params: Dict = None) -> Optional[Any]:
        """Make GET request to Harbor API"""
        if not REQUESTS_AVAILABLE:
            return None

        try:
            session = self._get_session()
            response = session.get(
                f"{self.api_url}/{endpoint}",
                params=params or {},
                timeout=30,
                verify=True
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"Harbor API error for {endpoint}: {e}")
            return None

    def scan_registry(self) -> Dict[str, Any]:
        """Scan Harbor registry"""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library required for Harbor scanning")
            return {}

        if not self.username or not self.password:
            logger.warning("Harbor credentials not provided")
            return {}

        try:
            self._get_projects()
            self._get_repositories()
            self._get_artifacts()
        except Exception as e:
            logger.error(f"Error scanning Harbor: {e}")

        return self.data

    def _get_projects(self) -> List[Dict]:
        """Get list of projects in Harbor"""
        projects = []
        page = 1
        page_size = 100

        while True:
            result = self._api_get('projects', {
                'page': page,
                'page_size': page_size
            })

            if not result:
                break

            for project in result:
                projects.append({
                    'id': project['project_id'],
                    'name': project['name'],
                    'public': project.get('metadata', {}).get('public', 'false') == 'true',
                    'repo_count': project.get('repo_count', 0),
                    'creation_time': project.get('creation_time', ''),
                    'update_time': project.get('update_time', '')
                })

            if len(result) < page_size:
                break
            page += 1

        self.data['projects'] = projects
        return projects

    def _get_repositories(self) -> List[Dict]:
        """Get repositories from all projects"""
        repositories = []

        for project in self.data['projects']:
            project_name = project['name']

            result = self._api_get(f"projects/{project_name}/repositories", {
                'page_size': 100
            })

            if result:
                for repo in result:
                    repositories.append({
                        'project': project_name,
                        'name': repo['name'],
                        'artifact_count': repo.get('artifact_count', 0),
                        'pull_count': repo.get('pull_count', 0),
                        'update_time': repo.get('update_time', '')
                    })

        self.data['repositories'] = repositories
        return repositories

    def _get_artifacts(self) -> List[Dict]:
        """Get artifacts (images) from repositories"""
        artifacts = []

        for repo in self.data['repositories'][:50]:  # Limit to first 50 repos
            # repo name includes project prefix
            repo_name = repo['name']
            project_name = repo['project']

            # Extract just the repo name without project prefix
            if '/' in repo_name:
                repo_short = repo_name.split('/', 1)[1]
            else:
                repo_short = repo_name

            result = self._api_get(
                f"projects/{project_name}/repositories/{repo_short}/artifacts",
                {'page_size': 10, 'with_tag': True, 'with_scan_overview': True}
            )

            if result:
                for artifact in result:
                    tags = [t['name'] for t in artifact.get('tags', []) or []]
                    scan_overview = artifact.get('scan_overview', {})

                    artifacts.append({
                        'repository': repo_name,
                        'project': project_name,
                        'digest': artifact.get('digest', '')[:20],
                        'tags': tags,
                        'size': artifact.get('size', 0),
                        'push_time': artifact.get('push_time', ''),
                        'scan_status': self._get_scan_status(scan_overview),
                        'vulnerabilities': self._get_vulnerability_summary(scan_overview)
                    })

        self.data['artifacts'] = artifacts
        return artifacts

    def _get_scan_status(self, scan_overview: Dict) -> str:
        """Extract scan status from overview"""
        if not scan_overview:
            return 'not_scanned'

        for scanner, data in scan_overview.items():
            return data.get('scan_status', 'unknown')

        return 'unknown'

    def _get_vulnerability_summary(self, scan_overview: Dict) -> Dict:
        """Extract vulnerability summary from scan overview"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        if not scan_overview:
            return summary

        for scanner, data in scan_overview.items():
            vuln_summary = data.get('summary', {}).get('summary', {})
            summary['critical'] = vuln_summary.get('Critical', 0)
            summary['high'] = vuln_summary.get('High', 0)
            summary['medium'] = vuln_summary.get('Medium', 0)
            summary['low'] = vuln_summary.get('Low', 0)
            break

        return summary

    def get_image_tags(self, project: str, repository: str) -> List[str]:
        """Get all tags for a specific image"""
        tags = []

        result = self._api_get(
            f"projects/{project}/repositories/{repository}/artifacts",
            {'with_tag': True}
        )

        if result:
            for artifact in result:
                artifact_tags = artifact.get('tags', []) or []
                tags.extend([t['name'] for t in artifact_tags])

        return tags

    def find_images_for_hostname(self, hostname: str) -> List[Dict]:
        """Find images that might be related to a hostname"""
        related = []
        hostname_lower = hostname.lower()

        for artifact in self.data['artifacts']:
            repo_name = artifact['repository'].lower()
            if hostname_lower in repo_name or any(
                hostname_lower in tag.lower() for tag in artifact.get('tags', [])
            ):
                related.append(artifact)

        return related

    def get_recently_pushed(self, days: int = 7) -> List[Dict]:
        """Get recently pushed images"""
        recent = []
        cutoff = datetime.now().timestamp() - (days * 86400)

        for artifact in self.data['artifacts']:
            push_time = artifact.get('push_time', '')
            if push_time:
                try:
                    # Parse ISO format
                    push_dt = datetime.fromisoformat(push_time.replace('Z', '+00:00'))
                    if push_dt.timestamp() > cutoff:
                        recent.append(artifact)
                except ValueError:
                    pass

        return recent

    def get_project_summary(self) -> Dict:
        """Get summary of Harbor projects and their contents"""
        summary = {
            'total_projects': len(self.data['projects']),
            'total_repositories': len(self.data['repositories']),
            'total_artifacts': len(self.data['artifacts']),
            'projects': {}
        }

        for project in self.data['projects']:
            project_name = project['name']
            repos = [r for r in self.data['repositories'] if r['project'] == project_name]
            artifacts = [a for a in self.data['artifacts'] if a['project'] == project_name]

            summary['projects'][project_name] = {
                'repo_count': len(repos),
                'artifact_count': len(artifacts),
                'repositories': [r['name'] for r in repos]
            }

        return summary
