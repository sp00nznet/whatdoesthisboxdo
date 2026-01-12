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
import threading
import functools
from datetime import datetime
from io import StringIO
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


def analyze_server(job_id, hostname, username, password=None, ssh_key=None, port=22, os_type='linux'):
    """Background task to analyze a server."""
    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['message'] = f'Connecting to {hostname}...'

        # Analyze the server based on OS type
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
            analyzer = SystemAnalyzer(winrm_config=winrm_config)
            data = analyzer.run_windows_analysis()
        else:
            ssh_config = SSHConfig(
                hostname=hostname,
                username=username,
                password=password if password else None,
                private_key_path=ssh_key if ssh_key else None,
                port=port
            )
            analyzer = SystemAnalyzer(remote_config=ssh_config)
            data = analyzer.run_remote_analysis()

        # Generate documentation
        jobs[job_id]['message'] = 'Generating documentation...'
        doc_gen = DocumentationGenerator()
        markdown = doc_gen.generate(data)
        html = doc_gen.generate_html(data)

        # Save outputs
        safe_hostname = hostname.replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{safe_hostname}_{timestamp}"

        md_path = OUTPUT_FOLDER / f"{base_name}.md"
        html_path = OUTPUT_FOLDER / f"{base_name}.html"
        json_path = OUTPUT_FOLDER / f"{base_name}.json"

        with open(md_path, 'w') as f:
            f.write(markdown)
        with open(html_path, 'w') as f:
            f.write(html)
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['message'] = 'Analysis complete!'
        jobs[job_id]['result'] = {
            'hostname': hostname,
            'markdown_file': str(md_path.name),
            'html_file': str(html_path.name),
            'json_file': str(json_path.name),
            'data': data
        }

    except Exception as e:
        jobs[job_id]['status'] = 'failed'
        jobs[job_id]['message'] = f'Error: {str(e)}'
        jobs[job_id]['error'] = str(e)


@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Single server analysis page."""
    if request.method == 'POST':
        # Check if using saved credential
        saved_credential_id = request.form.get('saved_credential', '').strip()

        if saved_credential_id:
            # Use saved credential
            cred = get_credential(credential_id=int(saved_credential_id))
            if not cred:
                flash('Selected credential not found', 'error')
                return render_template('analyze.html')

            hostname = cred['hostname']
            username = cred['username']
            password = cred.get('password', '')
            ssh_key = cred.get('ssh_key', '')
            port = cred['port']
            os_type = cred['os_type']
        else:
            # Manual entry
            hostname = request.form.get('hostname', '').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            ssh_key = request.form.get('ssh_key', '').strip()
            port = int(request.form.get('port', 22))
            os_type = request.form.get('os_type', 'linux')

            if not hostname or not username:
                flash('Hostname and username are required', 'error')
                return render_template('analyze.html')

            if not password and not ssh_key:
                flash('Either password or SSH key is required', 'error')
                return render_template('analyze.html')

        # Create job
        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'status': 'pending',
            'message': 'Starting analysis...',
            'hostname': hostname,
            'created': datetime.now().isoformat()
        }

        # Start background thread
        thread = threading.Thread(
            target=analyze_server,
            args=(job_id, hostname, username, password, ssh_key, port, os_type)
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

        # Parse CSV
        try:
            content = file.read().decode('utf-8')
            reader = csv.DictReader(StringIO(content))

            batch_id = str(uuid.uuid4())[:8]
            created_jobs = []

            for row in reader:
                hostname = row.get('hostname', row.get('host', '')).strip()
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
                    'created': datetime.now().isoformat()
                }

                thread = threading.Thread(
                    target=analyze_server,
                    args=(job_id, hostname, username, password, ssh_key, port, os_type)
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


@app.route('/download/<filename>')
def download_doc(filename):
    """Download generated documentation."""
    file_path = OUTPUT_FOLDER / filename

    if not file_path.exists():
        flash('File not found', 'error')
        return redirect(url_for('docs_list'))

    return send_file(file_path, as_attachment=True)


@app.route('/docs')
def docs_list():
    """List all generated documentation."""
    docs = []

    for file in OUTPUT_FOLDER.glob('*'):
        if file.suffix in ['.md', '.html', '.json']:
            docs.append({
                'name': file.name,
                'type': file.suffix[1:].upper(),
                'size': file.stat().st_size,
                'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat()
            })

    # Sort by modification time (newest first)
    docs.sort(key=lambda x: x['modified'], reverse=True)

    return render_template('docs.html', docs=docs)


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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
