#!/usr/bin/env python3
"""
WhatDoesThisBoxDo - Web Interface
A containerized web UI for server analysis and documentation generation.
"""

import os
import sys
import csv
import json
import uuid
import shutil
import threading
import functools
import tempfile
import zipfile
from datetime import datetime
from io import StringIO, BytesIO
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session

# Add parent directory to path to import analyzer modules
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Change working directory to project root for relative imports
os.chdir(PARENT_DIR)

from analyzer import SystemAnalyzer
from generators.doc_generator import DocumentationGenerator
from generators.terraform_generator import TerraformGenerator
from generators.ansible_generator import AnsibleGenerator
from generators.ansible_full_generator import AnsibleFullGenerator
from generators.aws_generator import AWSGenerator
from generators.gcp_generator import GCPGenerator
from generators.azure_generator import AzureGenerator
from generators.cost_estimator import CostEstimator
from connectors.ssh_executor import SSHConfig

# Try to import WinRM support
try:
    from connectors.winrm_executor import WinRMConfig
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    WinRMConfig = None

# Import database module
from database import (
    init_db, admin_exists, create_admin_user, verify_admin_user, update_admin_login,
    change_admin_password, save_credential, get_credential, list_credentials,
    delete_credential, save_env_variable, get_env_variable, list_env_variables,
    delete_env_variable, load_env_variables_to_environ
)

# Load stored environment variables
load_env_variables_to_environ()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'whatdoesthisboxdo-dev-key')

# Configuration
UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
OUTPUT_FOLDER = Path(__file__).parent / 'output'
UPLOAD_FOLDER.mkdir(exist_ok=True)
OUTPUT_FOLDER.mkdir(exist_ok=True)

# Store job status
jobs = {}


def analyze_server(job_id, hostname, username, password=None, ssh_key=None, port=22, os_type='linux',
                   monitor_duration=0, generate_ansible=True, generate_ansible_full=True,
                   generate_terraform=True, generate_cloud=True):
    """Background task to analyze a server and generate all outputs."""
    temp_key_file = None
    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['message'] = f'Connecting to {hostname}...'

        # Create output directory for this analysis
        safe_hostname = hostname.replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{safe_hostname}_{timestamp}"
        server_output_dir = OUTPUT_FOLDER / base_name

        server_output_dir.mkdir(parents=True, exist_ok=True)

        # Analyze the server based on OS type
        if monitor_duration > 0:
            jobs[job_id]['message'] = f'Collecting metrics for {monitor_duration} seconds...'
        else:
            jobs[job_id]['message'] = 'Analyzing system...'

        if os_type == 'windows':
            if not WINRM_AVAILABLE:
                raise RuntimeError("Windows support requires pywinrm. Install with: pip3 install pywinrm")
            winrm_config = WinRMConfig(
                hostname=hostname,
                username=username,
                password=password,
                port=port if port != 22 else 5985
            )
            analyzer = SystemAnalyzer(winrm_config=winrm_config, monitor_duration=monitor_duration)
            data = analyzer.run_windows_analysis()
        else:
            # Handle SSH key - could be file content or file path
            ssh_key_path = None
            if ssh_key:
                if ssh_key.startswith('-----BEGIN'):
                    # SSH key content - write to temp file
                    temp_key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
                    temp_key_file.write(ssh_key)
                    temp_key_file.close()
                    os.chmod(temp_key_file.name, 0o600)
                    ssh_key_path = temp_key_file.name
                else:
                    # Assume it's a file path
                    ssh_key_path = ssh_key

            ssh_config = SSHConfig(
                hostname=hostname,
                username=username,
                password=password if password else None,
                private_key_path=ssh_key_path,
                port=port
            )
            analyzer = SystemAnalyzer(remote_config=ssh_config, monitor_duration=monitor_duration)
            data = analyzer.run_remote_analysis()

        # Generate documentation
        jobs[job_id]['message'] = 'Generating documentation...'
        doc_gen = DocumentationGenerator()
        markdown = doc_gen.generate(data)
        html = doc_gen.generate_html(data)

        # Save documentation outputs
        md_path = OUTPUT_FOLDER / f"{base_name}.md"
        html_path = OUTPUT_FOLDER / f"{base_name}.html"
        json_path = OUTPUT_FOLDER / f"{base_name}.json"

        with open(md_path, 'w') as f:
            f.write(markdown)
        with open(html_path, 'w') as f:
            f.write(html)
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        # Initialize result with files
        result = {
            'hostname': hostname,
            'markdown_file': str(md_path.name),
            'html_file': str(html_path.name),
            'json_file': str(json_path.name),
            'output_dir': str(base_name),
            'data': data,
            'generated_outputs': {}
        }

        # Generate Ansible playbooks
        if generate_ansible:
            jobs[job_id]['message'] = 'Generating Ansible playbooks...'
            try:
                ansible_gen = AnsibleGenerator(data)
                ansible_path = ansible_gen.generate(str(server_output_dir / 'ansible'))
                result['generated_outputs']['ansible'] = 'ansible'
            except Exception as e:
                result['generated_outputs']['ansible_error'] = str(e)

        # Generate full Ansible recreation playbooks
        if generate_ansible_full:
            jobs[job_id]['message'] = 'Generating full Ansible recreation playbooks...'
            try:
                ansible_full_gen = AnsibleFullGenerator(data)
                ansible_full_path = ansible_full_gen.generate(str(server_output_dir / 'ansible-full'))
                result['generated_outputs']['ansible_full'] = 'ansible-full'
            except Exception as e:
                result['generated_outputs']['ansible_full_error'] = str(e)

        # Generate vSphere Terraform
        if generate_terraform:
            jobs[job_id]['message'] = 'Generating Terraform configs...'
            try:
                tf_gen = TerraformGenerator(data)
                tf_path = tf_gen.generate(str(server_output_dir / 'terraform-vsphere'))
                result['generated_outputs']['terraform_vsphere'] = 'terraform-vsphere'
            except Exception as e:
                result['generated_outputs']['terraform_vsphere_error'] = str(e)

        # Generate cloud provider configs
        if generate_cloud:
            # AWS
            jobs[job_id]['message'] = 'Generating AWS Terraform...'
            try:
                aws_gen = AWSGenerator(data)
                aws_path = aws_gen.generate(str(server_output_dir / 'terraform-aws'))
                result['generated_outputs']['terraform_aws'] = 'terraform-aws'
            except Exception as e:
                result['generated_outputs']['terraform_aws_error'] = str(e)

            # GCP
            jobs[job_id]['message'] = 'Generating GCP Terraform...'
            try:
                gcp_gen = GCPGenerator(data)
                gcp_path = gcp_gen.generate(str(server_output_dir / 'terraform-gcp'))
                result['generated_outputs']['terraform_gcp'] = 'terraform-gcp'
            except Exception as e:
                result['generated_outputs']['terraform_gcp_error'] = str(e)

            # Azure
            jobs[job_id]['message'] = 'Generating Azure Terraform...'
            try:
                azure_gen = AzureGenerator(data)
                azure_path = azure_gen.generate(str(server_output_dir / 'terraform-azure'))
                result['generated_outputs']['terraform_azure'] = 'terraform-azure'
            except Exception as e:
                result['generated_outputs']['terraform_azure_error'] = str(e)

            # Cost estimate
            jobs[job_id]['message'] = 'Generating cost estimates...'
            try:
                cost_estimator = CostEstimator(data)
                cost_report = cost_estimator.generate_report()
                cost_path = server_output_dir / 'cost-estimate.json'
                with open(cost_path, 'w') as f:
                    json.dump(cost_report, f, indent=2)
                result['generated_outputs']['cost_estimate'] = 'cost-estimate.json'
            except Exception as e:
                result['generated_outputs']['cost_estimate_error'] = str(e)

        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['message'] = 'Analysis complete!'
        jobs[job_id]['result'] = result

    except Exception as e:
        jobs[job_id]['status'] = 'failed'
        jobs[job_id]['message'] = f'Error: {str(e)}'
        jobs[job_id]['error'] = str(e)
    finally:
        # Clean up temp key file if created
        if temp_key_file and os.path.exists(temp_key_file.name):
            try:
                os.unlink(temp_key_file.name)
            except:
                pass


@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Single server analysis page."""
    if request.method == 'POST':
        # Get connection details from form (these can be overridden even with saved credential)
        hostname = request.form.get('hostname', '').strip()
        port = int(request.form.get('port', 22))
        os_type = request.form.get('os_type', 'linux')

        # Get analysis options
        monitor_duration = int(request.form.get('monitor_duration', 0))
        generate_ansible = request.form.get('generate_ansible') == '1'
        generate_ansible_full = request.form.get('generate_ansible_full') == '1'
        generate_terraform = request.form.get('generate_terraform') == '1'
        generate_cloud = request.form.get('generate_cloud') == '1'

        # Check if using saved credential
        saved_credential_id = request.form.get('saved_credential', '').strip()

        if saved_credential_id:
            # Use saved credential for authentication
            cred = get_credential(credential_id=int(saved_credential_id))
            if not cred:
                flash('Selected credential not found', 'error')
                return render_template('analyze.html')

            username = cred['username']
            password = cred.get('password', '')
            ssh_key = cred.get('ssh_key', '')

            # Use credential defaults for hostname/port/os_type only if not provided in form
            if not hostname and cred.get('hostname'):
                hostname = cred['hostname']
        else:
            # Manual entry
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            ssh_key = request.form.get('ssh_key', '').strip()

            if not password and not ssh_key:
                flash('Either password or SSH key is required', 'error')
                return render_template('analyze.html')

        # Validate required fields
        if not hostname:
            flash('Hostname is required', 'error')
            return render_template('analyze.html')

        if not username:
            flash('Username is required', 'error')
            return render_template('analyze.html')

        # Create job
        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'status': 'pending',
            'message': 'Starting analysis...',
            'hostname': hostname,
            'created': datetime.now().isoformat(),
            'options': {
                'monitor_duration': monitor_duration,
                'generate_ansible': generate_ansible,
                'generate_ansible_full': generate_ansible_full,
                'generate_terraform': generate_terraform,
                'generate_cloud': generate_cloud
            }
        }

        # Start background thread
        thread = threading.Thread(
            target=analyze_server,
            args=(job_id, hostname, username, password, ssh_key, port, os_type),
            kwargs={
                'monitor_duration': monitor_duration,
                'generate_ansible': generate_ansible,
                'generate_ansible_full': generate_ansible_full,
                'generate_terraform': generate_terraform,
                'generate_cloud': generate_cloud
            }
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('job_status', job_id=job_id))

    return render_template('analyze.html')


@app.route('/batch', methods=['GET', 'POST'])
def batch():
    """Batch processing via CSV upload."""
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file uploaded', 'error')
            return render_template('batch.html')

        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('batch.html')

        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'error')
            return render_template('batch.html')

        # Get analysis options
        monitor_duration = int(request.form.get('monitor_duration', 0))
        generate_ansible = request.form.get('generate_ansible') == '1'
        generate_ansible_full = request.form.get('generate_ansible_full') == '1'
        generate_terraform = request.form.get('generate_terraform') == '1'
        generate_cloud = request.form.get('generate_cloud') == '1'

        # Check for saved credential
        saved_cred = None
        saved_credential_id = request.form.get('saved_credential')
        if saved_credential_id:
            saved_cred = get_credential(credential_id=int(saved_credential_id))
            if not saved_cred:
                flash('Selected credential not found', 'error')
                return render_template('batch.html')

        # Parse CSV
        try:
            content = file.read().decode('utf-8')
            reader = csv.DictReader(StringIO(content))

            batch_id = str(uuid.uuid4())[:8]
            created_jobs = []

            for row in reader:
                hostname = row.get('hostname', row.get('host', '')).strip()

                # Use saved credential or CSV values
                if saved_cred:
                    username = saved_cred['username']
                    password = saved_cred.get('password', '')
                    ssh_key = saved_cred.get('ssh_key', '')
                    # Use CSV port/os_type if provided, otherwise use credential defaults
                    port = int(row.get('port', saved_cred.get('port', 22)))
                    os_type = row.get('os_type', row.get('os', saved_cred.get('os_type', 'linux'))).lower()
                else:
                    username = row.get('username', row.get('user', '')).strip()
                    password = row.get('password', row.get('pass', ''))
                    ssh_key = row.get('ssh_key', row.get('key', '')).strip()
                    port = int(row.get('port', 22))
                    os_type = row.get('os_type', row.get('os', 'linux')).lower()

                if not hostname or not username:
                    continue

                job_id = str(uuid.uuid4())
                jobs[job_id] = {
                    'status': 'pending',
                    'message': 'Queued for analysis...',
                    'hostname': hostname,
                    'batch_id': batch_id,
                    'created': datetime.now().isoformat(),
                    'options': {
                        'monitor_duration': monitor_duration,
                        'generate_ansible': generate_ansible,
                        'generate_ansible_full': generate_ansible_full,
                        'generate_terraform': generate_terraform,
                        'generate_cloud': generate_cloud
                    }
                }

                thread = threading.Thread(
                    target=analyze_server,
                    args=(job_id, hostname, username, password, ssh_key, port, os_type),
                    kwargs={
                        'monitor_duration': monitor_duration,
                        'generate_ansible': generate_ansible,
                        'generate_ansible_full': generate_ansible_full,
                        'generate_terraform': generate_terraform,
                        'generate_cloud': generate_cloud
                    }
                )
                thread.daemon = True
                thread.start()

                created_jobs.append({'job_id': job_id, 'hostname': hostname})

            if not created_jobs:
                flash('No valid servers found in CSV', 'error')
                return render_template('batch.html')

            flash(f'Started {len(created_jobs)} analysis jobs', 'success')
            return redirect(url_for('jobs_list', batch_id=batch_id))

        except Exception as e:
            flash(f'Error parsing CSV: {str(e)}', 'error')
            return render_template('batch.html')

    return render_template('batch.html')


@app.route('/jobs')
def jobs_list():
    """List all jobs."""
    batch_id = request.args.get('batch_id')

    job_list = []
    for job_id, job in jobs.items():
        if batch_id and job.get('batch_id') != batch_id:
            continue
        job_list.append({
            'id': job_id,
            **job
        })

    # Sort by creation time (newest first)
    job_list.sort(key=lambda x: x.get('created', ''), reverse=True)

    return render_template('jobs.html', jobs=job_list, batch_id=batch_id)


@app.route('/job/<job_id>')
def job_status(job_id):
    """View job status."""
    job = jobs.get(job_id)
    if not job:
        flash('Job not found', 'error')
        return redirect(url_for('jobs_list'))

    return render_template('job_status.html', job_id=job_id, job=job)


@app.route('/api/job/<job_id>')
def api_job_status(job_id):
    """API endpoint for job status."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify({'id': job_id, **job})


@app.route('/view/<filename>')
def view_doc(filename):
    """View generated documentation."""
    file_path = OUTPUT_FOLDER / filename

    if not file_path.exists():
        flash('File not found', 'error')
        return redirect(url_for('docs_list'))

    if filename.endswith('.html'):
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    elif filename.endswith('.md'):
        with open(file_path, 'r') as f:
            content = f.read()
        return render_template('view_markdown.html', content=content, filename=filename)
    elif filename.endswith('.json'):
        with open(file_path, 'r') as f:
            data = json.load(f)
        return render_template('view_json.html', data=data, filename=filename)
    else:
        flash('Unsupported file type', 'error')
        return redirect(url_for('docs_list'))


@app.route('/download/<path:filename>')
def download_doc(filename):
    """Download generated documentation or output file."""
    # Security: prevent path traversal
    safe_path = Path(filename)
    if '..' in safe_path.parts:
        flash('Invalid file path', 'error')
        return redirect(url_for('docs_list'))

    file_path = OUTPUT_FOLDER / safe_path

    if not file_path.exists():
        flash('File not found', 'error')
        return redirect(url_for('docs_list'))

    return send_file(file_path, as_attachment=True)


def create_zip_from_directory(source_dir, zip_name):
    """Create a ZIP file from a directory and return BytesIO object."""
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(source_dir)
                zf.write(file_path, arcname)
    memory_file.seek(0)
    return memory_file


@app.route('/download/output/<output_dir>/<output_type>')
def download_output(output_dir, output_type):
    """Download generated Ansible or Terraform output as ZIP."""
    # Security: validate path components
    safe_output_dir = Path(output_dir).name
    safe_output_type = Path(output_type).name

    # Map output types to directories
    output_type_map = {
        'ansible': 'ansible',
        'ansible-full': 'ansible-full',
        'terraform-vsphere': 'terraform-vsphere',
        'terraform-aws': 'terraform-aws',
        'terraform-gcp': 'terraform-gcp',
        'terraform-azure': 'terraform-azure',
        'all-terraform': None,  # Special case - all terraform combined
        'all': None  # Special case - all outputs
    }

    if safe_output_type not in output_type_map:
        flash('Invalid output type', 'error')
        return redirect(url_for('docs_list'))

    output_path = OUTPUT_FOLDER / safe_output_dir

    if not output_path.exists() or not output_path.is_dir():
        flash('Output directory not found', 'error')
        return redirect(url_for('docs_list'))

    # Handle special cases for combined downloads
    if safe_output_type == 'all-terraform':
        # Combine all terraform outputs
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for tf_type in ['terraform-vsphere', 'terraform-aws', 'terraform-gcp', 'terraform-azure']:
                tf_path = output_path / tf_type
                if tf_path.exists():
                    for root, dirs, files in os.walk(tf_path):
                        for file in files:
                            file_path = Path(root) / file
                            arcname = Path(tf_type) / file_path.relative_to(tf_path)
                            zf.write(file_path, arcname)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{safe_output_dir}_all_terraform.zip'
        )
    elif safe_output_type == 'all':
        # All outputs including ansible
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in output_path.iterdir():
                if item.is_dir():
                    for root, dirs, files in os.walk(item):
                        for file in files:
                            file_path = Path(root) / file
                            arcname = Path(item.name) / file_path.relative_to(item)
                            zf.write(file_path, arcname)
                else:
                    zf.write(item, item.name)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{safe_output_dir}_all_outputs.zip'
        )

    # Single output type
    target_dir = output_path / output_type_map[safe_output_type]
    if not target_dir.exists():
        flash(f'{safe_output_type} output not found', 'error')
        return redirect(url_for('docs_list'))

    memory_file = create_zip_from_directory(target_dir, safe_output_type)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{safe_output_dir}_{safe_output_type}.zip'
    )


@app.route('/docs')
def docs_list():
    """List all generated documentation and IaC outputs."""
    docs = []
    outputs = []

    for item in OUTPUT_FOLDER.iterdir():
        if item.is_file() and item.suffix in ['.md', '.html', '.json']:
            docs.append({
                'name': item.name,
                'type': item.suffix[1:].upper(),
                'size': item.stat().st_size,
                'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
            })
        elif item.is_dir():
            # Check for IaC outputs in this directory
            available = {
                'ansible': (item / 'ansible').exists(),
                'ansible_full': (item / 'ansible-full').exists(),
                'terraform_vsphere': (item / 'terraform-vsphere').exists(),
                'terraform_aws': (item / 'terraform-aws').exists(),
                'terraform_gcp': (item / 'terraform-gcp').exists(),
                'terraform_azure': (item / 'terraform-azure').exists(),
                'cost_estimate': (item / 'cost-estimate.json').exists()
            }

            # Only include if at least one output is available
            if any(available.values()):
                outputs.append({
                    'name': item.name,
                    'available': available,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })

    # Sort by modification time (newest first)
    docs.sort(key=lambda x: x['modified'], reverse=True)
    outputs.sort(key=lambda x: x['modified'], reverse=True)

    return render_template('docs.html', docs=docs, outputs=outputs)


@app.route('/api/docs')
def api_docs_list():
    """API endpoint for documentation list."""
    docs = []

    for file in OUTPUT_FOLDER.glob('*'):
        if file.suffix in ['.md', '.html', '.json']:
            docs.append({
                'name': file.name,
                'type': file.suffix[1:],
                'size': file.stat().st_size,
                'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat()
            })

    docs.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify(docs)


# =============================================================================
# Admin Routes
# =============================================================================

def admin_required(f):
    """Decorator to require admin login."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access the admin area', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    # If no admin exists, redirect to setup
    if not admin_exists():
        return redirect(url_for('admin_setup'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if verify_admin_user(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            update_admin_login(username)
            flash('Logged in successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('admin/login.html')


@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """Initial admin setup - create first admin user."""
    if admin_exists():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
        elif password != confirm:
            flash('Passwords do not match', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
        else:
            if create_admin_user(username, password):
                flash('Admin account created. Please log in.', 'success')
                return redirect(url_for('admin_login'))
            else:
                flash('Failed to create admin account', 'error')

    return render_template('admin/setup.html')


@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    credentials = list_credentials()
    env_vars = list_env_variables()
    return render_template('admin/dashboard.html',
                          credentials=credentials,
                          env_vars=env_vars)


# Credential Management Routes

@app.route('/admin/credentials')
@admin_required
def admin_credentials():
    """List all credentials."""
    credentials = list_credentials()
    return render_template('admin/credentials.html', credentials=credentials)


@app.route('/admin/credentials/add', methods=['GET', 'POST'])
@admin_required
def admin_add_credential():
    """Add a new credential."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        hostname = request.form.get('hostname', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        port = int(request.form.get('port', 22))
        os_type = request.form.get('os_type', 'linux')
        description = request.form.get('description', '').strip()

        # Handle SSH key file upload
        ssh_key = ''
        ssh_key_file = request.files.get('ssh_key_file')
        if ssh_key_file and ssh_key_file.filename:
            try:
                ssh_key = ssh_key_file.read().decode('utf-8')
            except UnicodeDecodeError:
                flash('Invalid SSH key file - must be a text file', 'error')
                return render_template('admin/credential_form.html', credential=None)

        if not name or not username:
            flash('Name and username are required', 'error')
        elif not password and not ssh_key:
            flash('Either password or SSH key file is required', 'error')
        else:
            save_credential(name, hostname, username, password, ssh_key, port, os_type, description)
            flash(f'Credential "{name}" saved successfully', 'success')
            return redirect(url_for('admin_credentials'))

    return render_template('admin/credential_form.html', credential=None)


@app.route('/admin/credentials/<int:cred_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_credential(cred_id):
    """Edit a credential."""
    credential = get_credential(credential_id=cred_id)
    if not credential:
        flash('Credential not found', 'error')
        return redirect(url_for('admin_credentials'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        hostname = request.form.get('hostname', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        port = int(request.form.get('port', 22))
        os_type = request.form.get('os_type', 'linux')
        description = request.form.get('description', '').strip()

        # Handle SSH key file upload
        ssh_key = ''
        replace_key = request.form.get('replace_key') == '1'
        ssh_key_file = request.files.get('ssh_key_file')

        if replace_key and ssh_key_file and ssh_key_file.filename:
            try:
                ssh_key = ssh_key_file.read().decode('utf-8')
            except UnicodeDecodeError:
                flash('Invalid SSH key file - must be a text file', 'error')
                return render_template('admin/credential_form.html', credential=credential)
        elif not replace_key and credential.get('ssh_key'):
            # Keep existing SSH key
            ssh_key = credential['ssh_key']

        # Keep existing password if not provided
        if not password and credential.get('password'):
            password = credential['password']

        if not name or not username:
            flash('Name and username are required', 'error')
        else:
            save_credential(name, hostname, username, password, ssh_key, port, os_type, description)
            flash(f'Credential "{name}" updated successfully', 'success')
            return redirect(url_for('admin_credentials'))

    return render_template('admin/credential_form.html', credential=credential)


@app.route('/admin/credentials/<int:cred_id>/delete', methods=['POST'])
@admin_required
def admin_delete_credential(cred_id):
    """Delete a credential."""
    if delete_credential(cred_id):
        flash('Credential deleted successfully', 'success')
    else:
        flash('Failed to delete credential', 'error')
    return redirect(url_for('admin_credentials'))


# Environment Variable Routes

@app.route('/admin/env')
@admin_required
def admin_env_vars():
    """List all environment variables."""
    env_vars = list_env_variables()
    return render_template('admin/env_vars.html', env_vars=env_vars)


@app.route('/admin/env/add', methods=['GET', 'POST'])
@admin_required
def admin_add_env_var():
    """Add a new environment variable."""
    if request.method == 'POST':
        key = request.form.get('key', '').strip().upper()
        value = request.form.get('value', '')
        description = request.form.get('description', '').strip()

        if not key or not value:
            flash('Key and value are required', 'error')
        else:
            save_env_variable(key, value, description)
            # Also set in current environment
            os.environ[key] = value
            flash(f'Environment variable "{key}" saved successfully', 'success')
            return redirect(url_for('admin_env_vars'))

    return render_template('admin/env_form.html', env_var=None)


@app.route('/admin/env/<key>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_env_var(key):
    """Edit an environment variable."""
    env_vars = list_env_variables(include_values=True)
    env_var = next((v for v in env_vars if v['key'] == key), None)

    if not env_var:
        flash('Environment variable not found', 'error')
        return redirect(url_for('admin_env_vars'))

    if request.method == 'POST':
        new_key = request.form.get('key', '').strip().upper()
        value = request.form.get('value', '')
        description = request.form.get('description', '').strip()

        if not new_key or not value:
            flash('Key and value are required', 'error')
        else:
            # If key changed, delete old one
            if new_key != key:
                delete_env_variable(key)
                if key in os.environ:
                    del os.environ[key]

            save_env_variable(new_key, value, description)
            os.environ[new_key] = value
            flash(f'Environment variable "{new_key}" updated successfully', 'success')
            return redirect(url_for('admin_env_vars'))

    return render_template('admin/env_form.html', env_var=env_var)


@app.route('/admin/env/<key>/delete', methods=['POST'])
@admin_required
def admin_delete_env_var(key):
    """Delete an environment variable."""
    if delete_env_variable(key):
        if key in os.environ:
            del os.environ[key]
        flash('Environment variable deleted successfully', 'success')
    else:
        flash('Failed to delete environment variable', 'error')
    return redirect(url_for('admin_env_vars'))


@app.route('/admin/password', methods=['GET', 'POST'])
@admin_required
def admin_change_password():
    """Change admin password."""
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        username = session.get('admin_username')

        if not verify_admin_user(username, current):
            flash('Current password is incorrect', 'error')
        elif new_password != confirm:
            flash('New passwords do not match', 'error')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
        else:
            if change_admin_password(username, new_password):
                flash('Password changed successfully', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Failed to change password', 'error')

    return render_template('admin/change_password.html')


# API endpoint to get credentials for analyze form
@app.route('/api/credentials')
def api_list_credentials():
    """API endpoint to list credentials (without secrets) for dropdown."""
    credentials = list_credentials(include_secrets=False)
    return jsonify([{
        'id': c['id'],
        'name': c['name'],
        'hostname': c['hostname'],
        'port': c['port'],
        'os_type': c['os_type']
    } for c in credentials])


# =============================================================================
# REST API v1
# =============================================================================

def api_key_required(f):
    """Decorator to require API key authentication."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        stored_key = os.environ.get('API_KEY', '')

        if not stored_key:
            return jsonify({'error': 'API not configured. Set API_KEY environment variable.'}), 503

        if not api_key or api_key != stored_key:
            return jsonify({'error': 'Invalid or missing API key'}), 401

        return f(*args, **kwargs)
    return decorated_function


def api_response(data=None, error=None, status=200):
    """Helper to create consistent API responses."""
    response = {'success': error is None}
    if data is not None:
        response['data'] = data
    if error:
        response['error'] = error
    return jsonify(response), status


@app.route('/api/v1/analyze', methods=['POST'])
@api_key_required
def api_analyze():
    """
    Start a single server analysis.

    POST /api/v1/analyze
    Headers: X-API-Key: <your-api-key>
    Body (JSON):
        {
            "hostname": "server.example.com",
            "username": "root",
            "password": "secret",      // or use ssh_key
            "ssh_key": "...",          // SSH private key content
            "port": 22,                // optional, default 22
            "os_type": "linux",        // optional: linux or windows
            "credential_id": 1,        // optional: use saved credential instead
            "monitor_duration": 60,    // optional: metrics collection duration in seconds (0 = disabled)
            "generate_ansible": true,  // optional: generate basic Ansible playbooks (default: true)
            "generate_ansible_full": true,  // optional: generate full recreation playbooks (default: true)
            "generate_terraform": true,     // optional: generate vSphere Terraform (default: true)
            "generate_cloud": true     // optional: generate AWS/GCP/Azure configs (default: true)
        }
    """
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    hostname = data.get('hostname', '').strip()
    credential_id = data.get('credential_id')

    # Get generation options
    monitor_duration = int(data.get('monitor_duration', 0))
    generate_ansible = data.get('generate_ansible', True)
    generate_ansible_full = data.get('generate_ansible_full', True)
    generate_terraform = data.get('generate_terraform', True)
    generate_cloud = data.get('generate_cloud', True)

    if credential_id:
        cred = get_credential(credential_id=int(credential_id))
        if not cred:
            return api_response(error='Credential not found', status=404)
        username = cred['username']
        password = cred.get('password', '')
        ssh_key = cred.get('ssh_key', '')
        port = data.get('port', cred.get('port', 22))
        os_type = data.get('os_type', cred.get('os_type', 'linux'))
        if not hostname and cred.get('hostname'):
            hostname = cred['hostname']
    else:
        username = data.get('username', '').strip()
        password = data.get('password', '')
        ssh_key = data.get('ssh_key', '')
        port = data.get('port', 22)
        os_type = data.get('os_type', 'linux')

    if not hostname:
        return api_response(error='hostname is required', status=400)
    if not username:
        return api_response(error='username is required', status=400)
    if not credential_id and not password and not ssh_key:
        return api_response(error='password or ssh_key is required', status=400)

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'pending',
        'message': 'Starting analysis...',
        'hostname': hostname,
        'created': datetime.now().isoformat(),
        'options': {
            'monitor_duration': monitor_duration,
            'generate_ansible': generate_ansible,
            'generate_ansible_full': generate_ansible_full,
            'generate_terraform': generate_terraform,
            'generate_cloud': generate_cloud
        }
    }

    thread = threading.Thread(
        target=analyze_server,
        args=(job_id, hostname, username, password, ssh_key, port, os_type),
        kwargs={
            'monitor_duration': monitor_duration,
            'generate_ansible': generate_ansible,
            'generate_ansible_full': generate_ansible_full,
            'generate_terraform': generate_terraform,
            'generate_cloud': generate_cloud
        }
    )
    thread.daemon = True
    thread.start()

    return api_response(data={
        'job_id': job_id,
        'status': 'pending',
        'message': 'Analysis started'
    }, status=202)


@app.route('/api/v1/batch', methods=['POST'])
@api_key_required
def api_batch():
    """
    Start batch analysis for multiple servers.

    POST /api/v1/batch
    Headers: X-API-Key: <your-api-key>
    Body (JSON):
        {
            "servers": [
                {"hostname": "server1.example.com"},
                {"hostname": "server2.example.com", "port": 2222}
            ],
            "credential_id": 1,         // Apply this credential to all servers
            "monitor_duration": 60,     // optional: metrics collection duration in seconds (0 = disabled)
            "generate_ansible": true,   // optional: generate basic Ansible playbooks (default: true)
            "generate_ansible_full": true,  // optional: generate full recreation playbooks (default: true)
            "generate_terraform": true,     // optional: generate vSphere Terraform (default: true)
            "generate_cloud": true      // optional: generate AWS/GCP/Azure configs (default: true)
        }
        // OR include credentials per server:
        {
            "servers": [
                {"hostname": "server1.example.com", "username": "root", "password": "secret"},
                {"hostname": "server2.example.com", "username": "admin", "ssh_key": "..."}
            ],
            "monitor_duration": 30
        }
    """
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    servers = data.get('servers', [])
    if not servers:
        return api_response(error='servers array is required', status=400)

    # Get generation options (apply to all servers in batch)
    monitor_duration = int(data.get('monitor_duration', 0))
    generate_ansible = data.get('generate_ansible', True)
    generate_ansible_full = data.get('generate_ansible_full', True)
    generate_terraform = data.get('generate_terraform', True)
    generate_cloud = data.get('generate_cloud', True)

    credential_id = data.get('credential_id')
    saved_cred = None
    if credential_id:
        saved_cred = get_credential(credential_id=int(credential_id))
        if not saved_cred:
            return api_response(error='Credential not found', status=404)

    batch_id = str(uuid.uuid4())[:8]
    created_jobs = []

    for server in servers:
        hostname = server.get('hostname', '').strip()
        if not hostname:
            continue

        if saved_cred:
            username = saved_cred['username']
            password = saved_cred.get('password', '')
            ssh_key = saved_cred.get('ssh_key', '')
            port = server.get('port', saved_cred.get('port', 22))
            os_type = server.get('os_type', saved_cred.get('os_type', 'linux'))
        else:
            username = server.get('username', '').strip()
            password = server.get('password', '')
            ssh_key = server.get('ssh_key', '')
            port = server.get('port', 22)
            os_type = server.get('os_type', 'linux')

        if not username:
            continue

        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'status': 'pending',
            'message': 'Queued for analysis...',
            'hostname': hostname,
            'batch_id': batch_id,
            'created': datetime.now().isoformat(),
            'options': {
                'monitor_duration': monitor_duration,
                'generate_ansible': generate_ansible,
                'generate_ansible_full': generate_ansible_full,
                'generate_terraform': generate_terraform,
                'generate_cloud': generate_cloud
            }
        }

        thread = threading.Thread(
            target=analyze_server,
            args=(job_id, hostname, username, password, ssh_key, port, os_type),
            kwargs={
                'monitor_duration': monitor_duration,
                'generate_ansible': generate_ansible,
                'generate_ansible_full': generate_ansible_full,
                'generate_terraform': generate_terraform,
                'generate_cloud': generate_cloud
            }
        )
        thread.daemon = True
        thread.start()

        created_jobs.append({'job_id': job_id, 'hostname': hostname})

    if not created_jobs:
        return api_response(error='No valid servers found', status=400)

    return api_response(data={
        'batch_id': batch_id,
        'jobs': created_jobs,
        'count': len(created_jobs)
    }, status=202)


@app.route('/api/v1/jobs', methods=['GET'])
@api_key_required
def api_list_jobs():
    """
    List all jobs.

    GET /api/v1/jobs
    GET /api/v1/jobs?batch_id=abc123
    GET /api/v1/jobs?status=running
    """
    batch_id = request.args.get('batch_id')
    status_filter = request.args.get('status')

    job_list = []
    for job_id, job in jobs.items():
        if batch_id and job.get('batch_id') != batch_id:
            continue
        if status_filter and job.get('status') != status_filter:
            continue

        job_list.append({
            'job_id': job_id,
            'status': job.get('status'),
            'message': job.get('message'),
            'hostname': job.get('hostname'),
            'batch_id': job.get('batch_id'),
            'created': job.get('created')
        })

    job_list.sort(key=lambda x: x['created'], reverse=True)
    return api_response(data={'jobs': job_list, 'count': len(job_list)})


@app.route('/api/v1/jobs/<job_id>', methods=['GET'])
@api_key_required
def api_get_job(job_id):
    """
    Get job status and details.

    GET /api/v1/jobs/<job_id>
    """
    job = jobs.get(job_id)
    if not job:
        return api_response(error='Job not found', status=404)

    result = {
        'job_id': job_id,
        'status': job.get('status'),
        'message': job.get('message'),
        'hostname': job.get('hostname'),
        'batch_id': job.get('batch_id'),
        'created': job.get('created'),
        'error': job.get('error'),
        'options': job.get('options')
    }

    if job.get('status') == 'completed' and job.get('result'):
        result['files'] = {
            'markdown': job['result'].get('markdown_file'),
            'html': job['result'].get('html_file'),
            'json': job['result'].get('json_file')
        }
        result['output_dir'] = job['result'].get('output_dir')
        result['generated_outputs'] = job['result'].get('generated_outputs', {})

        # Include download URLs for generated outputs
        output_dir = job['result'].get('output_dir')
        if output_dir:
            result['download_urls'] = {
                output_type: f'/api/v1/outputs/{output_dir}/{output_type}'
                for output_type in result['generated_outputs'].keys()
                if not output_type.endswith('_error')
            }

    return api_response(data=result)


@app.route('/api/v1/jobs/<job_id>/result', methods=['GET'])
@api_key_required
def api_get_job_result(job_id):
    """
    Get job result data.

    GET /api/v1/jobs/<job_id>/result
    GET /api/v1/jobs/<job_id>/result?format=json  (default)
    GET /api/v1/jobs/<job_id>/result?format=markdown
    GET /api/v1/jobs/<job_id>/result?format=html
    """
    job = jobs.get(job_id)
    if not job:
        return api_response(error='Job not found', status=404)

    if job.get('status') != 'completed':
        return api_response(error=f'Job is not completed (status: {job.get("status")})', status=400)

    result = job.get('result', {})
    format_type = request.args.get('format', 'json')

    if format_type == 'json':
        return api_response(data=result.get('data', {}))
    elif format_type == 'markdown':
        md_file = result.get('markdown_file')
        if md_file:
            md_path = OUTPUT_FOLDER / md_file
            if md_path.exists():
                return send_file(md_path, mimetype='text/markdown')
        return api_response(error='Markdown file not found', status=404)
    elif format_type == 'html':
        html_file = result.get('html_file')
        if html_file:
            html_path = OUTPUT_FOLDER / html_file
            if html_path.exists():
                return send_file(html_path, mimetype='text/html')
        return api_response(error='HTML file not found', status=404)
    else:
        return api_response(error='Invalid format. Use: json, markdown, or html', status=400)


@app.route('/api/v1/credentials', methods=['GET', 'POST'])
@api_key_required
def api_credentials_list():
    """
    List or create credentials.

    GET /api/v1/credentials - List all credentials
    POST /api/v1/credentials - Create a new credential
        Body: {"name": "...", "username": "...", "password": "...", ...}
    """
    if request.method == 'GET':
        credentials = list_credentials(include_secrets=False)
        return api_response(data={'credentials': credentials, 'count': len(credentials)})

    # POST - create credential
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    name = data.get('name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ssh_key = data.get('ssh_key', '')
    hostname = data.get('hostname', '').strip()
    port = data.get('port', 22)
    os_type = data.get('os_type', 'linux')
    description = data.get('description', '').strip()

    if not name:
        return api_response(error='name is required', status=400)
    if not username:
        return api_response(error='username is required', status=400)

    cred_id = save_credential(name, hostname, username, password, ssh_key, port, os_type, description)
    return api_response(data={'id': cred_id, 'name': name, 'message': 'Credential created'}, status=201)


@app.route('/api/v1/credentials/<int:cred_id>', methods=['GET', 'PUT', 'DELETE'])
@api_key_required
def api_credential_detail(cred_id):
    """
    Get, update, or delete a credential.

    GET /api/v1/credentials/<id> - Get credential details
    PUT /api/v1/credentials/<id> - Update credential
    DELETE /api/v1/credentials/<id> - Delete credential
    """
    credential = get_credential(credential_id=cred_id)
    if not credential:
        return api_response(error='Credential not found', status=404)

    if request.method == 'GET':
        # Return without secrets
        return api_response(data={
            'id': credential['id'],
            'name': credential['name'],
            'hostname': credential['hostname'],
            'username': credential['username'],
            'port': credential['port'],
            'os_type': credential['os_type'],
            'description': credential['description'],
            'has_password': credential['has_password'],
            'has_ssh_key': credential['has_ssh_key'],
            'created_at': str(credential['created_at']),
            'updated_at': str(credential['updated_at'])
        })

    if request.method == 'DELETE':
        if delete_credential(cred_id):
            return api_response(data={'message': 'Credential deleted'})
        return api_response(error='Failed to delete credential', status=500)

    # PUT - update credential
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    name = data.get('name', credential['name']).strip()
    username = data.get('username', credential['username']).strip()
    password = data.get('password', credential.get('password', ''))
    ssh_key = data.get('ssh_key', credential.get('ssh_key', ''))
    hostname = data.get('hostname', credential['hostname']).strip() if data.get('hostname') is not None else credential['hostname']
    port = data.get('port', credential['port'])
    os_type = data.get('os_type', credential['os_type'])
    description = data.get('description', credential.get('description', '')).strip()

    save_credential(name, hostname, username, password, ssh_key, port, os_type, description)
    return api_response(data={'id': cred_id, 'message': 'Credential updated'})


@app.route('/api/v1/docs', methods=['GET'])
@api_key_required
def api_list_docs():
    """
    List all generated documentation files.

    GET /api/v1/docs
    """
    docs = []
    for f in OUTPUT_FOLDER.glob('*.json'):
        stat = f.stat()
        base_name = f.stem
        docs.append({
            'name': base_name,
            'files': {
                'json': f.name,
                'markdown': f'{base_name}.md' if (OUTPUT_FOLDER / f'{base_name}.md').exists() else None,
                'html': f'{base_name}.html' if (OUTPUT_FOLDER / f'{base_name}.html').exists() else None
            },
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
        })

    docs.sort(key=lambda x: x['created'], reverse=True)
    return api_response(data={'documents': docs, 'count': len(docs)})


@app.route('/api/v1/docs/<filename>', methods=['GET'])
@api_key_required
def api_get_doc(filename):
    """
    Download a documentation file.

    GET /api/v1/docs/<filename>
    """
    # Security: prevent path traversal
    safe_filename = Path(filename).name
    file_path = OUTPUT_FOLDER / safe_filename

    if not file_path.exists():
        return api_response(error='File not found', status=404)

    mimetype = 'application/octet-stream'
    if safe_filename.endswith('.json'):
        mimetype = 'application/json'
    elif safe_filename.endswith('.md'):
        mimetype = 'text/markdown'
    elif safe_filename.endswith('.html'):
        mimetype = 'text/html'

    return send_file(file_path, mimetype=mimetype)


@app.route('/api/v1/outputs', methods=['GET'])
@api_key_required
def api_list_outputs():
    """
    List all generated output directories with their available downloads.

    GET /api/v1/outputs
    """
    outputs = []
    for item in OUTPUT_FOLDER.iterdir():
        if item.is_dir():
            output_info = {
                'name': item.name,
                'available_outputs': {}
            }
            # Check what outputs exist
            for output_type in ['ansible', 'ansible-full', 'terraform-vsphere',
                               'terraform-aws', 'terraform-gcp', 'terraform-azure']:
                if (item / output_type).exists():
                    output_info['available_outputs'][output_type] = True
            if (item / 'cost-estimate.json').exists():
                output_info['available_outputs']['cost_estimate'] = True

            if output_info['available_outputs']:
                outputs.append(output_info)

    return api_response(data={'outputs': outputs, 'count': len(outputs)})


@app.route('/api/v1/outputs/<output_dir>/<output_type>', methods=['GET'])
@api_key_required
def api_download_output(output_dir, output_type):
    """
    Download generated Ansible or Terraform output as ZIP.

    GET /api/v1/outputs/<output_dir>/<output_type>

    Available output types:
        - ansible: Basic Ansible playbooks
        - ansible-full: Full system recreation playbooks
        - terraform-vsphere: vSphere Terraform configuration
        - terraform-aws: AWS Terraform configuration
        - terraform-gcp: GCP Terraform configuration
        - terraform-azure: Azure Terraform configuration
        - all-terraform: All Terraform configs combined
        - all: All outputs combined
    """
    # Security: validate path components
    safe_output_dir = Path(output_dir).name
    safe_output_type = Path(output_type).name

    output_type_map = {
        'ansible': 'ansible',
        'ansible-full': 'ansible-full',
        'terraform-vsphere': 'terraform-vsphere',
        'terraform-aws': 'terraform-aws',
        'terraform-gcp': 'terraform-gcp',
        'terraform-azure': 'terraform-azure',
        'all-terraform': None,
        'all': None
    }

    if safe_output_type not in output_type_map:
        return api_response(error='Invalid output type', status=400)

    output_path = OUTPUT_FOLDER / safe_output_dir

    if not output_path.exists() or not output_path.is_dir():
        return api_response(error='Output directory not found', status=404)

    # Handle special cases for combined downloads
    if safe_output_type == 'all-terraform':
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for tf_type in ['terraform-vsphere', 'terraform-aws', 'terraform-gcp', 'terraform-azure']:
                tf_path = output_path / tf_type
                if tf_path.exists():
                    for root, dirs, files in os.walk(tf_path):
                        for file in files:
                            file_path = Path(root) / file
                            arcname = Path(tf_type) / file_path.relative_to(tf_path)
                            zf.write(file_path, arcname)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{safe_output_dir}_all_terraform.zip'
        )
    elif safe_output_type == 'all':
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in output_path.iterdir():
                if item.is_dir():
                    for root, dirs, files in os.walk(item):
                        for file in files:
                            file_path = Path(root) / file
                            arcname = Path(item.name) / file_path.relative_to(item)
                            zf.write(file_path, arcname)
                else:
                    zf.write(item, item.name)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{safe_output_dir}_all_outputs.zip'
        )

    # Single output type
    target_dir = output_path / output_type_map[safe_output_type]
    if not target_dir.exists():
        return api_response(error=f'{safe_output_type} output not found', status=404)

    memory_file = create_zip_from_directory(target_dir, safe_output_type)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{safe_output_dir}_{safe_output_type}.zip'
    )


@app.route('/api/v1/jobs/<job_id>/outputs', methods=['GET'])
@api_key_required
def api_job_outputs(job_id):
    """
    List available outputs for a completed job.

    GET /api/v1/jobs/<job_id>/outputs
    """
    job = jobs.get(job_id)
    if not job:
        return api_response(error='Job not found', status=404)

    if job.get('status') != 'completed':
        return api_response(error=f'Job is not completed (status: {job.get("status")})', status=400)

    result = job.get('result', {})
    output_dir = result.get('output_dir')
    generated_outputs = result.get('generated_outputs', {})

    if not output_dir:
        return api_response(error='No output directory for this job', status=404)

    return api_response(data={
        'output_dir': output_dir,
        'generated_outputs': generated_outputs,
        'download_urls': {
            output_type: f'/api/v1/outputs/{output_dir}/{output_type}'
            for output_type in generated_outputs.keys()
            if not output_type.endswith('_error')
        }
    })


@app.route('/api/v1/jobs/<job_id>/outputs/<output_type>', methods=['GET'])
@api_key_required
def api_job_output_download(job_id, output_type):
    """
    Download a specific output from a completed job.

    GET /api/v1/jobs/<job_id>/outputs/<output_type>
    """
    job = jobs.get(job_id)
    if not job:
        return api_response(error='Job not found', status=404)

    if job.get('status') != 'completed':
        return api_response(error=f'Job is not completed (status: {job.get("status")})', status=400)

    result = job.get('result', {})
    output_dir = result.get('output_dir')

    if not output_dir:
        return api_response(error='No output directory for this job', status=404)

    # Delegate to the download_output function
    return api_download_output(output_dir, output_type)


# =============================================================================
# Datadog Integration Routes
# =============================================================================

# Import Datadog-related database functions
from database import (
    save_datadog_credential, get_datadog_credential, list_datadog_credentials,
    delete_datadog_credential, save_pattern, get_patterns, is_novel_pattern,
    save_insight, get_insights, resolve_insight, save_analysis_history,
    get_analysis_history, save_baseline, get_baselines
)

# Import Datadog connector if available
try:
    from connectors.datadog_connector import DatadogConnector, DatadogConfig
    from analyzers.datadog_analyzer import DatadogAnalyzer
    from generators.containerization_planner import ContainerizationPlanner
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False
    DatadogConnector = None
    DatadogConfig = None
    DatadogAnalyzer = None
    ContainerizationPlanner = None


def analyze_datadog_host(job_id, hostname, dd_credential_id=None, api_key=None, app_key=None,
                         site='datadoghq.com', lookback_hours=24, save_to_db=True):
    """Background task to analyze a server via Datadog API."""
    import hashlib

    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['message'] = f'Connecting to Datadog for {hostname}...'

        if not DATADOG_AVAILABLE:
            raise RuntimeError("Datadog support not available")

        # Get credentials
        if dd_credential_id:
            cred = get_datadog_credential(credential_id=int(dd_credential_id))
            if not cred:
                raise RuntimeError("Datadog credential not found")
            api_key = cred['api_key']
            app_key = cred['app_key']
            site = cred.get('site', 'datadoghq.com')
        elif not api_key or not app_key:
            raise RuntimeError("API key and App key are required")

        # Create connector
        config = DatadogConfig(api_key=api_key, app_key=app_key, site=site)
        connector = DatadogConnector(config)

        # Test connection
        jobs[job_id]['message'] = 'Testing Datadog API connection...'
        if not connector.test_connection():
            raise RuntimeError("Failed to connect to Datadog API - check credentials")

        # Fetch data
        jobs[job_id]['message'] = f'Fetching {lookback_hours}h of metrics for {hostname}...'
        datadog_data = connector.get_all_data_for_host(
            hostname,
            lookback_hours=lookback_hours,
            include_processes=True
        )

        if not datadog_data or not datadog_data.get('metrics'):
            raise RuntimeError(f"No Datadog data found for host: {hostname}")

        # Run analysis
        jobs[job_id]['message'] = 'Analyzing metrics and detecting patterns...'
        analyzer = DatadogAnalyzer()
        analysis_results = analyzer.analyze(datadog_data)

        # Save to database if requested
        if save_to_db:
            jobs[job_id]['message'] = 'Saving results to database...'

            # Save analysis history
            save_analysis_history(
                hostname=hostname,
                health_score=analysis_results.get('health_score', 0),
                server_types=analysis_results.get('server_types', []),
                critical_count=analysis_results.get('summary', {}).get('critical_issues', 0),
                warning_count=analysis_results.get('summary', {}).get('warnings', 0),
                pattern_count=len(analysis_results.get('patterns', [])),
                analysis_data=analysis_results
            )

            # Save patterns and check for novel ones
            novel_patterns = []
            for pattern in analysis_results.get('patterns', []):
                # Create a hash for the pattern
                pattern_str = f"{pattern['pattern_type']}:{pattern['description']}:{','.join(pattern['metrics_involved'])}"
                pattern_hash = hashlib.sha256(pattern_str.encode()).hexdigest()[:16]

                is_novel = is_novel_pattern(pattern_hash)
                if is_novel:
                    novel_patterns.append(pattern)

                save_pattern(
                    pattern_hash=pattern_hash,
                    pattern_type=pattern['pattern_type'],
                    description=pattern['description'],
                    metrics_involved=pattern['metrics_involved'],
                    server_type=analysis_results.get('server_types', [None])[0] if analysis_results.get('server_types') else None,
                    confidence=pattern['confidence'],
                    metadata=pattern.get('metadata')
                )

            # Save insights
            for insight in analysis_results.get('insights', []):
                insight_str = f"{hostname}:{insight['category']}:{insight['title']}"
                insight_hash = hashlib.sha256(insight_str.encode()).hexdigest()[:16]

                save_insight(
                    hostname=hostname,
                    insight_hash=insight_hash,
                    category=insight['category'],
                    severity=insight['severity'],
                    title=insight['title'],
                    description=insight.get('description'),
                    metric_name=insight.get('metric_name'),
                    metric_value=insight.get('metric_value'),
                    threshold=insight.get('threshold'),
                    suggested_action=insight.get('suggested_action')
                )

            # Save baselines
            for metric_name, metric_data in datadog_data.get('metrics', {}).items():
                if metric_data.get('values'):
                    values = metric_data['values']
                    avg = sum(values) / len(values)
                    std_dev = (sum((x - avg) ** 2 for x in values) / len(values)) ** 0.5

                    save_baseline(
                        hostname=hostname,
                        metric_name=metric_name,
                        baseline_avg=avg,
                        baseline_min=metric_data.get('min', min(values)),
                        baseline_max=metric_data.get('max', max(values)),
                        baseline_stddev=std_dev,
                        sample_count=len(values)
                    )

            analysis_results['novel_patterns'] = novel_patterns

        # Store results
        result = {
            'hostname': hostname,
            'lookback_hours': lookback_hours,
            'analysis': analysis_results,
            'raw_data': {
                'host_info': datadog_data.get('host_info'),
                'tags': datadog_data.get('tags', []),
                'metrics_summary': {
                    name: {
                        'avg': data.get('avg'),
                        'min': data.get('min'),
                        'max': data.get('max'),
                        'sample_count': data.get('sample_count')
                    }
                    for name, data in datadog_data.get('metrics', {}).items()
                },
                'monitors': datadog_data.get('monitors', []),
                'events': datadog_data.get('events', [])[:10]  # Limit events in response
            }
        }

        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['message'] = 'Datadog analysis complete!'
        jobs[job_id]['result'] = result

    except Exception as e:
        jobs[job_id]['status'] = 'failed'
        jobs[job_id]['message'] = f'Error: {str(e)}'
        jobs[job_id]['error'] = str(e)


@app.route('/datadog')
def datadog_dashboard():
    """Datadog integration dashboard."""
    credentials = list_datadog_credentials()
    recent_analyses = get_analysis_history(limit=10)
    open_insights = get_insights(status='open', limit=20)
    patterns = get_patterns(min_occurrences=1, limit=20)

    return render_template('datadog/dashboard.html',
                          credentials=credentials,
                          recent_analyses=recent_analyses,
                          open_insights=open_insights,
                          patterns=patterns,
                          datadog_available=DATADOG_AVAILABLE)


@app.route('/datadog/analyze', methods=['GET', 'POST'])
def datadog_analyze():
    """Analyze a server using Datadog data."""
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        lookback_hours = int(request.form.get('lookback_hours', 24))
        save_to_db = request.form.get('save_to_db') == '1'

        # Get credentials
        dd_credential_id = request.form.get('dd_credential_id', '').strip()
        api_key = request.form.get('api_key', '').strip()
        app_key = request.form.get('app_key', '').strip()
        site = request.form.get('site', 'datadoghq.com').strip()

        if not hostname:
            flash('Hostname is required', 'error')
            return render_template('datadog/analyze.html', credentials=list_datadog_credentials())

        if not dd_credential_id and (not api_key or not app_key):
            flash('Either select saved credentials or provide API key and App key', 'error')
            return render_template('datadog/analyze.html', credentials=list_datadog_credentials())

        # Create job
        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'status': 'pending',
            'message': 'Starting Datadog analysis...',
            'hostname': hostname,
            'type': 'datadog',
            'created': datetime.now().isoformat()
        }

        # Start background thread
        thread = threading.Thread(
            target=analyze_datadog_host,
            args=(job_id, hostname),
            kwargs={
                'dd_credential_id': dd_credential_id if dd_credential_id else None,
                'api_key': api_key if not dd_credential_id else None,
                'app_key': app_key if not dd_credential_id else None,
                'site': site,
                'lookback_hours': lookback_hours,
                'save_to_db': save_to_db
            }
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('job_status', job_id=job_id))

    credentials = list_datadog_credentials()
    return render_template('datadog/analyze.html', credentials=credentials)


@app.route('/datadog/insights')
def datadog_insights():
    """View Datadog insights."""
    hostname = request.args.get('hostname')
    severity = request.args.get('severity')
    status = request.args.get('status', 'open')

    insights = get_insights(hostname=hostname, severity=severity, status=status, limit=100)
    return render_template('datadog/insights.html', insights=insights)


@app.route('/datadog/insights/<int:insight_id>/resolve', methods=['POST'])
@admin_required
def datadog_resolve_insight(insight_id):
    """Resolve a Datadog insight."""
    resolution_notes = request.form.get('resolution_notes', '')
    if resolve_insight(insight_id, resolution_notes):
        flash('Insight resolved successfully', 'success')
    else:
        flash('Failed to resolve insight', 'error')
    return redirect(url_for('datadog_insights'))


@app.route('/datadog/patterns')
def datadog_patterns():
    """View learned patterns."""
    pattern_type = request.args.get('type')
    server_type = request.args.get('server_type')
    min_occurrences = int(request.args.get('min_occurrences', 1))

    patterns = get_patterns(
        pattern_type=pattern_type,
        server_type=server_type,
        min_occurrences=min_occurrences,
        limit=100
    )
    return render_template('datadog/patterns.html', patterns=patterns)


@app.route('/datadog/history')
def datadog_history():
    """View analysis history."""
    hostname = request.args.get('hostname')
    history = get_analysis_history(hostname=hostname, limit=50)
    return render_template('datadog/history.html', history=history)


# Admin routes for Datadog credentials
@app.route('/admin/datadog')
@admin_required
def admin_datadog():
    """Admin page for Datadog credentials."""
    credentials = list_datadog_credentials()
    return render_template('admin/datadog.html', credentials=credentials)


@app.route('/admin/datadog/add', methods=['GET', 'POST'])
@admin_required
def admin_add_datadog_credential():
    """Add a new Datadog credential."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        api_key = request.form.get('api_key', '').strip()
        app_key = request.form.get('app_key', '').strip()
        site = request.form.get('site', 'datadoghq.com').strip()
        description = request.form.get('description', '').strip()

        if not name or not api_key or not app_key:
            flash('Name, API key, and App key are required', 'error')
        else:
            save_datadog_credential(name, api_key, app_key, site, description)
            flash(f'Datadog credential "{name}" saved successfully', 'success')
            return redirect(url_for('admin_datadog'))

    return render_template('admin/datadog_form.html', credential=None)


@app.route('/admin/datadog/<int:cred_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_datadog_credential(cred_id):
    """Edit a Datadog credential."""
    credential = get_datadog_credential(credential_id=cred_id)
    if not credential:
        flash('Credential not found', 'error')
        return redirect(url_for('admin_datadog'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        api_key = request.form.get('api_key', '').strip()
        app_key = request.form.get('app_key', '').strip()
        site = request.form.get('site', 'datadoghq.com').strip()
        description = request.form.get('description', '').strip()

        # Keep existing keys if not provided
        if not api_key:
            api_key = credential['api_key']
        if not app_key:
            app_key = credential['app_key']

        if not name:
            flash('Name is required', 'error')
        else:
            save_datadog_credential(name, api_key, app_key, site, description)
            flash(f'Datadog credential "{name}" updated successfully', 'success')
            return redirect(url_for('admin_datadog'))

    return render_template('admin/datadog_form.html', credential=credential)


@app.route('/admin/datadog/<int:cred_id>/delete', methods=['POST'])
@admin_required
def admin_delete_datadog_credential(cred_id):
    """Delete a Datadog credential."""
    if delete_datadog_credential(cred_id):
        flash('Datadog credential deleted successfully', 'success')
    else:
        flash('Failed to delete credential', 'error')
    return redirect(url_for('admin_datadog'))


# API endpoints for Datadog
@app.route('/api/v1/datadog/analyze', methods=['POST'])
@api_key_required
def api_datadog_analyze():
    """
    Analyze a server using Datadog data.

    POST /api/v1/datadog/analyze
    Headers: X-API-Key: <your-api-key>
    Body (JSON):
        {
            "hostname": "server.example.com",
            "lookback_hours": 24,
            "dd_credential_id": 1,  // OR provide api_key and app_key
            "api_key": "...",       // Datadog API key
            "app_key": "...",       // Datadog App key
            "site": "datadoghq.com",
            "save_to_db": true
        }
    """
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    hostname = data.get('hostname', '').strip()
    if not hostname:
        return api_response(error='hostname is required', status=400)

    lookback_hours = int(data.get('lookback_hours', 24))
    save_to_db = data.get('save_to_db', True)
    dd_credential_id = data.get('dd_credential_id')
    api_key = data.get('api_key', '').strip()
    app_key = data.get('app_key', '').strip()
    site = data.get('site', 'datadoghq.com')

    if not dd_credential_id and (not api_key or not app_key):
        return api_response(error='dd_credential_id or api_key/app_key are required', status=400)

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'pending',
        'message': 'Starting Datadog analysis...',
        'hostname': hostname,
        'type': 'datadog',
        'created': datetime.now().isoformat()
    }

    thread = threading.Thread(
        target=analyze_datadog_host,
        args=(job_id, hostname),
        kwargs={
            'dd_credential_id': dd_credential_id,
            'api_key': api_key if not dd_credential_id else None,
            'app_key': app_key if not dd_credential_id else None,
            'site': site,
            'lookback_hours': lookback_hours,
            'save_to_db': save_to_db
        }
    )
    thread.daemon = True
    thread.start()

    return api_response(data={
        'job_id': job_id,
        'status': 'pending',
        'message': 'Datadog analysis started'
    }, status=202)


@app.route('/api/v1/datadog/credentials', methods=['GET', 'POST'])
@api_key_required
def api_datadog_credentials():
    """List or create Datadog credentials."""
    if request.method == 'GET':
        credentials = list_datadog_credentials(include_secrets=False)
        return api_response(data={'credentials': credentials, 'count': len(credentials)})

    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    name = data.get('name', '').strip()
    api_key = data.get('api_key', '').strip()
    app_key = data.get('app_key', '').strip()
    site = data.get('site', 'datadoghq.com')
    description = data.get('description', '').strip()

    if not name or not api_key or not app_key:
        return api_response(error='name, api_key, and app_key are required', status=400)

    cred_id = save_datadog_credential(name, api_key, app_key, site, description)
    return api_response(data={'id': cred_id, 'name': name, 'message': 'Credential created'}, status=201)


@app.route('/api/v1/datadog/insights', methods=['GET'])
@api_key_required
def api_datadog_insights():
    """Get Datadog insights."""
    hostname = request.args.get('hostname')
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 100))

    insights = get_insights(hostname=hostname, severity=severity, status=status, limit=limit)
    return api_response(data={'insights': insights, 'count': len(insights)})


@app.route('/api/v1/datadog/patterns', methods=['GET'])
@api_key_required
def api_datadog_patterns():
    """Get learned patterns."""
    pattern_type = request.args.get('type')
    server_type = request.args.get('server_type')
    min_occurrences = int(request.args.get('min_occurrences', 1))
    limit = int(request.args.get('limit', 100))

    patterns = get_patterns(
        pattern_type=pattern_type,
        server_type=server_type,
        min_occurrences=min_occurrences,
        limit=limit
    )
    return api_response(data={'patterns': patterns, 'count': len(patterns)})


@app.route('/api/v1/datadog/history', methods=['GET'])
@api_key_required
def api_datadog_history():
    """Get analysis history."""
    hostname = request.args.get('hostname')
    limit = int(request.args.get('limit', 50))

    history = get_analysis_history(hostname=hostname, limit=limit)
    return api_response(data={'history': history, 'count': len(history)})


@app.route('/api/v1/datadog/baselines/<hostname>', methods=['GET'])
@api_key_required
def api_datadog_baselines(hostname):
    """Get baselines for a host."""
    baselines = get_baselines(hostname)
    return api_response(data={'hostname': hostname, 'baselines': baselines})


# =============================================================================
# Containerization Planner Routes
# =============================================================================

def generate_containerization_plan(job_id, hostname, dd_credential_id=None, api_key=None,
                                    app_key=None, site='datadoghq.com', lookback_hours=24):
    """Background task to generate containerization plan from Datadog data."""
    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['message'] = f'Fetching Datadog data for {hostname}...'

        if not DATADOG_AVAILABLE or not ContainerizationPlanner:
            raise RuntimeError("Containerization planner not available")

        # Get credentials
        if dd_credential_id:
            cred = get_datadog_credential(credential_id=int(dd_credential_id))
            if not cred:
                raise RuntimeError("Datadog credential not found")
            api_key = cred['api_key']
            app_key = cred['app_key']
            site = cred.get('site', 'datadoghq.com')
        elif not api_key or not app_key:
            raise RuntimeError("API key and App key are required")

        # Create connector and fetch data
        config = DatadogConfig(api_key=api_key, app_key=app_key, site=site)
        connector = DatadogConnector(config)

        if not connector.test_connection():
            raise RuntimeError("Failed to connect to Datadog API")

        jobs[job_id]['message'] = f'Fetching {lookback_hours}h of metrics...'
        datadog_data = connector.get_all_data_for_host(
            hostname, lookback_hours=lookback_hours, include_processes=True
        )

        if not datadog_data:
            raise RuntimeError(f"No data found for host: {hostname}")

        # Run analysis
        jobs[job_id]['message'] = 'Analyzing application patterns...'
        analyzer = DatadogAnalyzer()
        analysis_results = analyzer.analyze(datadog_data)

        # Generate containerization plan
        jobs[job_id]['message'] = 'Generating containerization plan...'
        planner = ContainerizationPlanner(datadog_data, analysis_results)
        plan = planner.analyze_and_plan()

        # Save output files
        output_dir = os.path.join('output', f'containerization-{hostname}-{datetime.now().strftime("%Y%m%d-%H%M%S")}')
        os.makedirs(output_dir, exist_ok=True)

        # Write all configuration files
        configs = plan.get('configurations', {})

        # Dockerfiles
        dockerfile_dir = os.path.join(output_dir, 'dockerfiles')
        os.makedirs(dockerfile_dir, exist_ok=True)
        for name, content in configs.get('dockerfiles', {}).items():
            with open(os.path.join(dockerfile_dir, f'Dockerfile.{name}'), 'w') as f:
                f.write(content)

        # docker-compose
        with open(os.path.join(output_dir, 'docker-compose.yml'), 'w') as f:
            f.write(configs.get('docker_compose', ''))

        # Kubernetes manifests
        k8s_dir = os.path.join(output_dir, 'kubernetes')
        os.makedirs(k8s_dir, exist_ok=True)
        for name, content in configs.get('kubernetes', {}).items():
            with open(os.path.join(k8s_dir, name), 'w') as f:
                f.write(content)

        # Full plan JSON
        with open(os.path.join(output_dir, 'plan.json'), 'w') as f:
            json.dump(plan, f, indent=2, default=str)

        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['message'] = 'Containerization plan generated successfully!'
        jobs[job_id]['result'] = {
            'hostname': hostname,
            'output_dir': output_dir,
            'plan': plan
        }

    except Exception as e:
        jobs[job_id]['status'] = 'failed'
        jobs[job_id]['message'] = f'Error: {str(e)}'
        jobs[job_id]['error'] = str(e)


@app.route('/datadog/containerize', methods=['GET', 'POST'])
def datadog_containerize():
    """Generate containerization plan from Datadog data."""
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        lookback_hours = int(request.form.get('lookback_hours', 24))
        dd_credential_id = request.form.get('dd_credential_id', '').strip()
        api_key = request.form.get('api_key', '').strip()
        app_key = request.form.get('app_key', '').strip()
        site = request.form.get('site', 'datadoghq.com').strip()

        if not hostname:
            flash('Hostname is required', 'error')
            return render_template('datadog/containerize.html', credentials=list_datadog_credentials())

        if not dd_credential_id and (not api_key or not app_key):
            flash('Either select saved credentials or provide API key and App key', 'error')
            return render_template('datadog/containerize.html', credentials=list_datadog_credentials())

        # Create job
        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'status': 'pending',
            'message': 'Starting containerization planning...',
            'hostname': hostname,
            'type': 'containerization',
            'created': datetime.now().isoformat()
        }

        thread = threading.Thread(
            target=generate_containerization_plan,
            args=(job_id, hostname),
            kwargs={
                'dd_credential_id': dd_credential_id if dd_credential_id else None,
                'api_key': api_key if not dd_credential_id else None,
                'app_key': app_key if not dd_credential_id else None,
                'site': site,
                'lookback_hours': lookback_hours
            }
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('job_status', job_id=job_id))

    credentials = list_datadog_credentials()
    return render_template('datadog/containerize.html', credentials=credentials)


@app.route('/datadog/containerize/result/<job_id>')
def datadog_containerize_result(job_id):
    """View containerization plan results."""
    if job_id not in jobs:
        flash('Job not found', 'error')
        return redirect(url_for('datadog_dashboard'))

    job = jobs[job_id]
    if job.get('status') != 'completed':
        return redirect(url_for('job_status', job_id=job_id))

    result = job.get('result', {})
    plan = result.get('plan', {})

    return render_template('datadog/containerize_result.html', job_id=job_id, plan=plan, result=result)


@app.route('/datadog/containerize/download/<job_id>/<file_type>')
def datadog_containerize_download(job_id, file_type):
    """Download containerization artifacts."""
    if job_id not in jobs:
        flash('Job not found', 'error')
        return redirect(url_for('datadog_dashboard'))

    job = jobs[job_id]
    result = job.get('result', {})
    output_dir = result.get('output_dir')

    if not output_dir or not os.path.exists(output_dir):
        flash('Output files not found', 'error')
        return redirect(url_for('datadog_containerize_result', job_id=job_id))

    if file_type == 'docker-compose':
        return send_from_directory(output_dir, 'docker-compose.yml', as_attachment=True)
    elif file_type == 'plan':
        return send_from_directory(output_dir, 'plan.json', as_attachment=True)
    elif file_type == 'all':
        # Create zip file
        import shutil
        zip_path = shutil.make_archive(output_dir, 'zip', output_dir)
        zip_name = os.path.basename(zip_path)
        return send_from_directory(os.path.dirname(zip_path), zip_name, as_attachment=True)
    else:
        flash('Invalid file type', 'error')
        return redirect(url_for('datadog_containerize_result', job_id=job_id))


# API endpoints for containerization
@app.route('/api/v1/datadog/containerize', methods=['POST'])
@api_key_required
def api_datadog_containerize():
    """
    Generate containerization plan from Datadog data.

    POST /api/v1/datadog/containerize
    Headers: X-API-Key: <your-api-key>
    Body (JSON):
        {
            "hostname": "server.example.com",
            "lookback_hours": 24,
            "dd_credential_id": 1,  // OR provide api_key and app_key
            "api_key": "...",
            "app_key": "...",
            "site": "datadoghq.com"
        }
    """
    data = request.get_json()
    if not data:
        return api_response(error='Request body must be JSON', status=400)

    hostname = data.get('hostname', '').strip()
    if not hostname:
        return api_response(error='hostname is required', status=400)

    lookback_hours = int(data.get('lookback_hours', 24))
    dd_credential_id = data.get('dd_credential_id')
    api_key = data.get('api_key', '').strip()
    app_key = data.get('app_key', '').strip()
    site = data.get('site', 'datadoghq.com')

    if not dd_credential_id and (not api_key or not app_key):
        return api_response(error='dd_credential_id or api_key/app_key are required', status=400)

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'pending',
        'message': 'Starting containerization planning...',
        'hostname': hostname,
        'type': 'containerization',
        'created': datetime.now().isoformat()
    }

    thread = threading.Thread(
        target=generate_containerization_plan,
        args=(job_id, hostname),
        kwargs={
            'dd_credential_id': dd_credential_id,
            'api_key': api_key if not dd_credential_id else None,
            'app_key': app_key if not dd_credential_id else None,
            'site': site,
            'lookback_hours': lookback_hours
        }
    )
    thread.daemon = True
    thread.start()

    return api_response(data={
        'job_id': job_id,
        'status': 'pending',
        'message': 'Containerization planning started'
    }, status=202)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
