"""
Windows Remote System Analyzer
Analyzes remote Windows systems via WinRM connection
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class WindowsProcessAnalyzer:
    """Analyzes processes on a remote Windows system via WinRM"""

    def __init__(self, winrm):
        self.winrm = winrm
        self.data = {
            'running': [],
            'services': [],
            'connections': [],
            'listening_ports': [],
            'resource_usage': {}
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full process analysis on remote Windows system"""
        self._get_running_processes()
        self._get_services()
        self._get_connections()
        self._get_resource_usage()
        return self.data

    def _get_running_processes(self) -> List[Dict]:
        """Get running processes from remote Windows system"""
        processes = []

        script = """
Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet64, Path, UserName -First 200 |
    ForEach-Object {
        @{
            'pid' = $_.Id
            'name' = $_.ProcessName
            'cpu_percent' = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
            'memory_bytes' = $_.WorkingSet64
            'exe' = $_.Path
            'user' = $_.UserName
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for proc in result:
                    proc['memory_percent'] = 0  # Calculate later with total memory
                    proc['cmdline'] = proc.get('exe', proc.get('name', ''))
                    processes.append(proc)
            except json.JSONDecodeError:
                logger.warning("Could not parse process list")

        self.data['running'] = processes
        return processes

    def _get_services(self) -> List[Dict]:
        """Get Windows services from remote system"""
        services = []

        script = """
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    ForEach-Object {
        @{
            'name' = $_.Name
            'display_name' = $_.DisplayName
            'status' = $_.Status.ToString()
            'start_type' = $_.StartType.ToString()
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for svc in result:
                    services.append({
                        'name': svc['name'],
                        'display_name': svc.get('display_name', svc['name']),
                        'active': 'running' if svc['status'] == 'Running' else 'stopped',
                        'status': svc['status'].lower(),
                        'start_type': svc.get('start_type', 'unknown')
                    })
            except json.JSONDecodeError:
                logger.warning("Could not parse service list")

        self.data['services'] = services
        return services

    def _get_connections(self) -> List[Dict]:
        """Get network connections from remote Windows system"""
        connections = []

        script = """
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    ForEach-Object {
        @{
            'local_addr' = $_.LocalAddress
            'local_port' = $_.LocalPort
            'remote_addr' = $_.RemoteAddress
            'remote_port' = $_.RemotePort
            'status' = $_.State.ToString()
            'pid' = $_.OwningProcess
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for conn in result:
                    connections.append({
                        'type': 'tcp',
                        'local_addr': conn['local_addr'],
                        'local_port': conn['local_port'],
                        'remote_addr': conn['remote_addr'],
                        'remote_port': conn['remote_port'],
                        'status': conn['status'],
                        'process': str(conn.get('pid', 'unknown'))
                    })
            except json.JSONDecodeError:
                logger.warning("Could not parse connection list")

        # Extract listening ports
        self.data['listening_ports'] = [
            {'port': c['local_port'], 'process': c['process'], 'addr': c['local_addr']}
            for c in connections if c['status'] == 'Listen' and c['local_port'] > 0
        ]

        self.data['connections'] = connections
        return connections

    def _get_resource_usage(self) -> Dict:
        """Get system resource usage from remote Windows system"""
        usage = {'cpu': {}, 'memory': {}, 'disk': {}, 'network': {}}

        # CPU and Memory info
        script = """
$cpu = Get-WmiObject Win32_Processor
$mem = Get-WmiObject Win32_OperatingSystem
$load = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue

@{
    'cpu_count' = ($cpu | Measure-Object).Count
    'cpu_name' = $cpu[0].Name
    'cpu_load' = if ($load) { [math]::Round($load, 1) } else { 0 }
    'memory_total' = $mem.TotalVisibleMemorySize * 1024
    'memory_free' = $mem.FreePhysicalMemory * 1024
    'memory_used' = ($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) * 1024
} | ConvertTo-Json
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                usage['cpu'] = {
                    'count': result.get('cpu_count', 0),
                    'name': result.get('cpu_name', ''),
                    'load_avg': [result.get('cpu_load', 0)]
                }
                total = result.get('memory_total', 0)
                used = result.get('memory_used', 0)
                usage['memory'] = {
                    'total': total,
                    'used': used,
                    'free': result.get('memory_free', 0),
                    'percent': round(used / total * 100, 1) if total > 0 else 0
                }
            except json.JSONDecodeError:
                pass

        # Disk usage
        script = """
Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" |
    ForEach-Object {
        @{
            'drive' = $_.DeviceID
            'total' = $_.Size
            'free' = $_.FreeSpace
            'used' = $_.Size - $_.FreeSpace
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for disk in result:
                    drive = disk.get('drive', 'C:')
                    total = disk.get('total', 0) or 0
                    used = disk.get('used', 0) or 0
                    usage['disk'][drive] = {
                        'total': int(total),
                        'used': int(used),
                        'free': int(disk.get('free', 0) or 0),
                        'percent': int(used / total * 100) if total > 0 else 0
                    }
            except json.JSONDecodeError:
                pass

        self.data['resource_usage'] = usage
        return usage


class WindowsFileAnalyzer:
    """Analyzes files and installed software on a remote Windows system via WinRM"""

    def __init__(self, winrm):
        self.winrm = winrm
        self.data = {
            'configurations': [],
            'installed_packages': [],
            'service_configs': {},
            'important_paths': [],
            'recently_modified': [],
            'installed_software': []
        }

    def analyze(self, paths: List[str] = None) -> Dict[str, Any]:
        """Run full file analysis on remote Windows system"""
        self._get_installed_software()
        self._get_installed_features()
        self._get_important_paths()
        self._get_recently_modified()
        self._get_scheduled_tasks()
        return self.data

    def _get_installed_software(self) -> List[Dict]:
        """Get installed software from remote Windows system"""
        packages = []

        script = """
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
    HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -First 200 |
    ForEach-Object {
        @{
            'name' = $_.DisplayName
            'version' = $_.DisplayVersion
            'publisher' = $_.Publisher
            'install_date' = $_.InstallDate
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for pkg in result:
                    packages.append({
                        'name': pkg.get('name', ''),
                        'version': pkg.get('version', ''),
                        'publisher': pkg.get('publisher', ''),
                        'manager': 'windows'
                    })
            except json.JSONDecodeError:
                pass

        self.data['installed_software'] = packages
        self.data['installed_packages'] = packages
        return packages

    def _get_installed_features(self) -> List[Dict]:
        """Get Windows features/roles"""
        features = []

        script = """
try {
    Get-WindowsFeature | Where-Object { $_.Installed } |
        Select-Object Name, DisplayName |
        ForEach-Object {
            @{
                'name' = $_.Name
                'display_name' = $_.DisplayName
            }
        } | ConvertTo-Json -Compress
} catch {
    # Get-WindowsFeature not available on non-server Windows
    Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } |
        Select-Object FeatureName |
        ForEach-Object {
            @{
                'name' = $_.FeatureName
                'display_name' = $_.FeatureName
            }
        } | ConvertTo-Json -Compress
}
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                for feat in result:
                    features.append({
                        'name': feat.get('name', ''),
                        'display_name': feat.get('display_name', ''),
                        'manager': 'windows_feature'
                    })
                    # Add to packages list as well
                    self.data['installed_packages'].append({
                        'name': feat.get('name', ''),
                        'version': 'feature',
                        'manager': 'windows_feature'
                    })
            except json.JSONDecodeError:
                pass

        return features

    def _get_important_paths(self) -> List[Dict]:
        """Get important directory information"""
        paths = []
        important_dirs = [
            'C:\\Windows\\System32\\config',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\Users',
            'C:\\inetpub\\wwwroot',
            'C:\\ProgramData'
        ]

        for dir_path in important_dirs:
            escaped_path = dir_path.replace("'", "''")
            script = f"""
if (Test-Path '{escaped_path}') {{
    $items = Get-ChildItem '{escaped_path}' -ErrorAction SilentlyContinue
    @{{
        'path' = '{dir_path}'
        'exists' = $true
        'contents_count' = ($items | Measure-Object).Count
    }} | ConvertTo-Json
}} else {{
    @{{'path' = '{dir_path}'; 'exists' = $false}} | ConvertTo-Json
}}
"""
            exit_code, stdout, _ = self.winrm.execute(script)
            if exit_code == 0 and stdout.strip():
                try:
                    result = json.loads(stdout)
                    if result.get('exists', False):
                        paths.append({
                            'path': result['path'],
                            'size': 0,  # Would require recursive calculation
                            'contents_count': result.get('contents_count', 0)
                        })
                except json.JSONDecodeError:
                    pass

        self.data['important_paths'] = paths
        return paths

    def _get_recently_modified(self) -> List[Dict]:
        """Get recently modified configuration files"""
        files = []

        script = """
Get-ChildItem -Path 'C:\\Windows\\System32\\config', 'C:\\ProgramData' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
    Select-Object FullName, Length, LastWriteTime -First 50 |
    ForEach-Object {
        @{
            'path' = $_.FullName
            'size' = $_.Length
            'modified' = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                files = result
            except json.JSONDecodeError:
                pass

        self.data['recently_modified'] = files
        return files

    def _get_scheduled_tasks(self) -> List[Dict]:
        """Get scheduled tasks"""
        tasks = []

        script = """
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } |
    Select-Object TaskName, TaskPath, State -First 50 |
    ForEach-Object {
        @{
            'name' = $_.TaskName
            'path' = $_.TaskPath
            'state' = $_.State.ToString()
        }
    } | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                tasks = result
            except json.JSONDecodeError:
                pass

        self.data['scheduled_tasks'] = tasks
        return tasks


class WindowsHistoryAnalyzer:
    """Analyzes PowerShell history on a remote Windows system via WinRM"""

    def __init__(self, winrm, users: List[str] = None):
        self.winrm = winrm
        self.users = users or []
        self.data = {
            'commands': [],
            'setup_commands': [],
            'package_installations': [],
            'service_changes': [],
            'config_changes': [],
            'users_analyzed': []
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full history analysis on remote Windows system"""
        users_to_check = self._get_users_to_analyze()
        self.data['users_analyzed'] = users_to_check

        all_commands = []

        for user in users_to_check:
            commands = self._read_user_history(user)
            all_commands.extend(commands)

        self.data['commands'] = all_commands
        self._categorize_commands(all_commands)

        return self.data

    def _get_users_to_analyze(self) -> List[str]:
        """Get list of users to analyze"""
        if self.users:
            return self.users

        users = []
        script = """
Get-ChildItem 'C:\\Users' -Directory |
    Where-Object { $_.Name -notmatch 'Public|Default' } |
    Select-Object -ExpandProperty Name |
    ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, str):
                    result = [result]
                users = result
            except json.JSONDecodeError:
                pass

        return users[:10]

    def _read_user_history(self, user: str) -> List[Dict]:
        """Read PowerShell history for a user"""
        commands = []

        # PowerShell history file location
        history_path = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
        escaped_path = history_path.replace("'", "''")

        script = f"""
if (Test-Path '{escaped_path}') {{
    Get-Content '{escaped_path}' -Tail 500 | ConvertTo-Json -Compress
}} else {{
    '[]'
}}
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, str):
                    result = [result]
                elif isinstance(result, dict):
                    # Single command as dict, skip
                    result = []
                for i, line in enumerate(result):
                    # Ensure line is a string
                    if isinstance(line, dict):
                        line = line.get('command', line.get('CommandLine', str(line)))
                    if isinstance(line, str) and line.strip():
                        commands.append({
                            'command': line.strip(),
                            'user': user,
                            'source': history_path,
                            'line': i + 1
                        })
            except json.JSONDecodeError:
                pass

        return commands

    def _categorize_commands(self, commands: List[Dict]) -> None:
        """Categorize commands by type"""
        setup_commands = []
        package_installations = []
        service_changes = []
        config_changes = []

        important_patterns = [
            r'Install-Package|Install-Module|choco install|winget install',
            r'Install-WindowsFeature|Enable-WindowsOptionalFeature',
            r'Set-Service|Start-Service|Stop-Service|Restart-Service',
            r'New-Item|Set-Content|Add-Content|Remove-Item',
            r'Set-ItemProperty|New-ItemProperty',
            r'netsh|New-NetFirewallRule',
            r'Add-LocalGroupMember|New-LocalUser',
        ]

        for cmd_info in commands:
            cmd = cmd_info['command']

            for pattern in important_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    setup_commands.append(cmd_info)

                    if re.search(r'Install-Package|Install-Module|choco|winget', cmd, re.IGNORECASE):
                        package_installations.append(cmd_info)
                    elif re.search(r'Service|WindowsFeature', cmd, re.IGNORECASE):
                        service_changes.append(cmd_info)
                    elif re.search(r'Set-|New-|Add-|Remove-|netsh', cmd, re.IGNORECASE):
                        config_changes.append(cmd_info)
                    break

        # Deduplicate
        seen = set()
        self.data['setup_commands'] = [c for c in setup_commands if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['package_installations'] = [c for c in package_installations if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['service_changes'] = [c for c in service_changes if c['command'] not in seen and not seen.add(c['command'])]
        seen.clear()
        self.data['config_changes'] = [c for c in config_changes if c['command'] not in seen and not seen.add(c['command'])]


class WindowsSecretsAnalyzer:
    """Analyzes certificates and credentials on a remote Windows system"""

    def __init__(self, winrm):
        self.winrm = winrm
        self.data = {
            'certificates': [],
            'credential_stores': [],
            'ssh_keys': [],
            'other_keys': []
        }

    def analyze(self) -> Dict[str, Any]:
        """Run full secrets analysis on remote Windows system"""
        self._find_certificates()
        self._find_ssh_keys()
        self._find_credential_stores()
        return self.data

    def _find_certificates(self) -> List[Dict]:
        """Find certificates in Windows certificate stores"""
        certs = []

        script = """
$stores = @('LocalMachine\\My', 'LocalMachine\\Root', 'CurrentUser\\My')
$certs = @()
foreach ($store in $stores) {
    try {
        $storePath = "Cert:\\$store"
        Get-ChildItem $storePath -ErrorAction SilentlyContinue | ForEach-Object {
            $certs += @{
                'store' = $store
                'subject' = $_.Subject
                'issuer' = $_.Issuer
                'thumbprint' = $_.Thumbprint
                'not_after' = $_.NotAfter.ToString('yyyy-MM-dd')
                'has_private_key' = $_.HasPrivateKey
            }
        }
    } catch {}
}
$certs | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                certs = result
            except json.JSONDecodeError:
                pass

        self.data['certificates'] = certs
        return certs

    def _find_ssh_keys(self) -> List[Dict]:
        """Find SSH keys on Windows system"""
        keys = []

        script = """
$keys = @()
$sshPaths = @(
    "$env:USERPROFILE\\.ssh",
    "C:\\ProgramData\\ssh",
    "C:\\Users\\*\\.ssh"
)
foreach ($path in $sshPaths) {
    Get-ChildItem $path -Filter 'id_*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '\\.pub$' } |
        ForEach-Object {
            $content = Get-Content $_.FullName -First 1 -ErrorAction SilentlyContinue
            $keys += @{
                'path' = $_.FullName
                'name' = $_.Name
                'type' = if ($content -match 'RSA') { 'RSA' }
                        elseif ($content -match 'EC') { 'ECDSA' }
                        elseif ($content -match 'ED25519|OPENSSH') { 'ED25519' }
                        else { 'unknown' }
                'encrypted' = $content -match 'ENCRYPTED'
            }
        }
}
$keys | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                keys = result
            except json.JSONDecodeError:
                pass

        self.data['ssh_keys'] = keys
        return keys

    def _find_credential_stores(self) -> List[Dict]:
        """Identify credential storage locations"""
        stores = []

        script = """
$stores = @()
# Check for Credential Manager entries count
$count = (cmdkey /list 2>$null | Select-String 'Target:').Count
$stores += @{
    'type' = 'Windows Credential Manager'
    'entry_count' = $count
}

# Check for DPAPI protected files
$dpapiPath = "$env:APPDATA\\Microsoft\\Protect"
if (Test-Path $dpapiPath) {
    $stores += @{
        'type' = 'DPAPI Master Keys'
        'path' = $dpapiPath
        'exists' = $true
    }
}

$stores | ConvertTo-Json -Compress
"""
        exit_code, stdout, _ = self.winrm.execute(script)

        if exit_code == 0 and stdout.strip():
            try:
                result = json.loads(stdout)
                if isinstance(result, dict):
                    result = [result]
                stores = result
            except json.JSONDecodeError:
                pass

        self.data['credential_stores'] = stores
        return stores


class WindowsSystemAnalyzer:
    """Orchestrates all Windows remote analysis"""

    def __init__(self, winrm):
        self.winrm = winrm
        self.hostname = winrm.get_hostname()

    def analyze_all(self, users: List[str] = None) -> Dict[str, Any]:
        """Run complete analysis on remote Windows system"""
        logger.info(f"Starting Windows analysis of {self.hostname}")

        data = {
            'hostname': self.hostname,
            'os_info': self.winrm.get_os_info(),
            'os_type': 'windows',
            'processes': {},
            'files': {},
            'history': {},
            'secrets': {}
        }

        # Process analysis
        logger.info("Analyzing processes...")
        process_analyzer = WindowsProcessAnalyzer(self.winrm)
        data['processes'] = process_analyzer.analyze()

        # File analysis
        logger.info("Analyzing files and installed software...")
        file_analyzer = WindowsFileAnalyzer(self.winrm)
        data['files'] = file_analyzer.analyze()

        # History analysis
        logger.info("Analyzing PowerShell history...")
        history_analyzer = WindowsHistoryAnalyzer(self.winrm, users)
        data['history'] = history_analyzer.analyze()

        # Secrets analysis
        logger.info("Analyzing certificates and credentials...")
        secrets_analyzer = WindowsSecretsAnalyzer(self.winrm)
        data['secrets'] = secrets_analyzer.analyze()

        logger.info(f"Windows analysis of {self.hostname} complete")
        return data
