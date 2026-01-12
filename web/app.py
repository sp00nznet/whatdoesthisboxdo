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
from datetime import datetime
from io import StringIO
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify

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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
