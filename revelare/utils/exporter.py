import os
import json
import shutil
import zipfile
from datetime import datetime
from typing import Dict, Any, List

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.utils import reporter as reporter_utils

logger = get_logger(__name__)


def _build_dashboard_meta(project_name: str, findings: Dict[str, Any]) -> Dict[str, Any]:
    total_indicators = sum(len(v) for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict))
    files_processed = findings.get("Processing_Summary", {}).get("Total_Files_Processed", 0)
    category_counts = {k: len(v) for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict)}
    top_categories = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:5]

    recent_indicators: List[Dict[str, Any]] = []
    count = 0
    for category, items in findings.items():
        if category == 'Processing_Summary':
            continue
        if isinstance(items, dict):
            for value, context in items.items():
                if count >= 10:
                    break
                file_source = "Unknown"
                if 'File:' in context:
                    file_source = context.split('File:')[1].split('|')[0].strip()
                recent_indicators.append({
                    'category': category,
                    'value': value,
                    'file_source': file_source
                })
                count += 1
        if count >= 10:
            break

    return {
        'project_name': project_name,
        'generation_date': datetime.now().isoformat(),
        'total_indicators': total_indicators,
        'files_processed': files_processed,
        'category_count': len(category_counts),
        'top_categories': top_categories,
        'recent_indicators': recent_indicators
    }


def _build_indicators(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for category, items in findings.items():
        if category == 'Processing_Summary' or not isinstance(items, dict):
            continue
        for value, context in items.items():
            file_source, position = "Unknown", "N/A"
            if 'File:' in context:
                file_source = context.split('File:')[1].split('|')[0].strip()
            if 'Position:' in context:
                position = context.split('Position:')[1].split('|')[0].strip()
            rows.append({
                'category': category,
                'value': value,
                'details': context,
                'file': file_source,
                'position': position
            })
    return rows


def _build_geographic(project_name: str, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Collect IPv4s
    ip_values: List[str] = []
    for category, items in findings.items():
        if 'IPv4' in str(category) and isinstance(items, dict):
            ip_values.extend(list(items.keys()))

    report_gen = reporter_utils.ReportGenerator()
    enriched = report_gen.enrich_ips(ip_values)

    rows: List[Dict[str, Any]] = []
    for ip, details in enriched.items():
        if not isinstance(details, dict):
            continue
        country = details.get('country') or ''
        city = details.get('city') or ''
        asn = details.get('asn') or details.get('asn_org') or details.get('org') or ''
        error = details.get('error')
        if error:
            risk = 'Low'
        else:
            risk = 'Medium' if country in {"RU", "CN", "KP", "IR"} else 'Low'

        indicators_count = 0
        for category, items in findings.items():
            if isinstance(items, dict) and 'IPv4' in str(category):
                if ip in items:
                    indicators_count += 1

        rows.append({
            'ip': ip,
            'country': country,
            'city': city,
            'asn': asn,
            'risk': risk,
            'indicators': indicators_count
        })
    return rows


def _build_files(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    file_map: Dict[str, Dict[str, Any]] = {}
    for category, items in findings.items():
        if category == 'Processing_Summary' or not isinstance(items, dict):
            continue
        for value, context in items.items():
            src = "Unknown"
            if 'File:' in context:
                src = context.split('File:')[1].split('|')[0].strip()
            entry = file_map.setdefault(src, {
                'name': src,
                'type': os.path.splitext(src)[1].lower().lstrip('.'),
                'size': 0,
                'indicators': 0,
                'status': 'normal'
            })
            entry['indicators'] += 1
    return list(file_map.values())


def _build_security(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    security_categories = {'IPv4_Suspect', 'Malicious_URL', 'CVE', 'Suspicious_Process', 'YARA_Match'}
    for category, items in findings.items():
        if category in security_categories and isinstance(items, dict):
            for value, context in items.items():
                file_source = "Unknown"
                if 'File:' in context:
                    file_source = context.split('File:')[1].split('|')[0].strip()
                rows.append({'category': category, 'value': value, 'details': context, 'file': file_source})
    return rows


def _build_technical(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for category, items in findings.items():
        if category == 'Processing_Summary' or not isinstance(items, dict):
            continue
        rows.append({'category': category, 'count': len(items)})
    return rows


def export_reader_package(project_name: str) -> str:
    project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
    findings_file = os.path.join(project_path, 'raw_findings.json')
    if not os.path.exists(findings_file):
        raise FileNotFoundError("Findings not found.")

    with open(findings_file, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_root = os.path.join(project_path, 'exports')
    os.makedirs(export_root, exist_ok=True)
    package_dir_name = f"{project_name}_report_{timestamp}"
    package_dir = os.path.join(export_root, package_dir_name)

    # Clean if exists
    if os.path.exists(package_dir):
        shutil.rmtree(package_dir, ignore_errors=True)
    os.makedirs(package_dir, exist_ok=True)

    # Prepare reader structure
    reader_dir = os.path.join(package_dir, 'reader')
    data_dir = os.path.join(reader_dir, 'data')
    templates_dir = os.path.join(reader_dir, 'templates')
    static_dir = os.path.join(reader_dir, 'static')
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)

    # Write datasets
    meta = _build_dashboard_meta(project_name, findings)
    indicators = _build_indicators(findings)
    geographic = _build_geographic(project_name, findings)
    files_rows = _build_files(findings)
    security_rows = _build_security(findings)
    technical_rows = _build_technical(findings)

    with open(os.path.join(data_dir, 'meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    with open(os.path.join(data_dir, 'indicators.json'), 'w', encoding='utf-8') as f:
        json.dump({'indicators': indicators}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(data_dir, 'geographic.json'), 'w', encoding='utf-8') as f:
        json.dump({'geographic': geographic}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(data_dir, 'files.json'), 'w', encoding='utf-8') as f:
        json.dump({'files': files_rows}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(data_dir, 'security.json'), 'w', encoding='utf-8') as f:
        json.dump({'security': security_rows}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(data_dir, 'technical.json'), 'w', encoding='utf-8') as f:
        json.dump({'technical': technical_rows}, f, indent=2, ensure_ascii=False)

    # Copy templates and static assets
    src_templates = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'web', 'templates')
    src_static = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'web', 'static')
    # Copy only report templates and base
    needed_templates = [
        'base.html',
        'report_nav.html',
        'report_dashboard.html',
        'report_indicators.html',
        'report_geographic.html',
        'report_files.html',
        'report_security.html',
        'report_technical.html'
    ]
    # Copy templates
    for name in needed_templates:
        src_path = os.path.join(src_templates, name)
        dest_path = os.path.join(templates_dir, name)

        if name == 'base.html':
            # Create a reader-specific base.html that removes problematic navigation links
            with open(src_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Remove navigation links that don't exist in reader app
            content = content.replace(
                '''                <a href="{{ url_for('email_browser') }}" class="nav-link">
                    <i class="fas fa-envelope"></i> Email Browser
                </a>
                <a href="{{ url_for('link_analysis') }}" class="nav-link">
                    <i class="fas fa-link"></i> Link Analysis
                </a>
                <a href="{{ url_for('string_search') }}" class="nav-link">
                    <i class="fas fa-search"></i> String Search
                </a>
                <a href="{{ url_for('fractal_encryption') }}" class="nav-link">
                    <i class="fas fa-snowflake"></i> Fractal Encryption
                </a>
                <a href="{{ url_for('settings') }}" class="nav-link">
                    <i class="fas fa-cog"></i> Settings
                </a>''',
                '''                <!-- Reader app only shows report navigation -->
                <span class="nav-link disabled">
                    <i class="fas fa-info-circle"></i> Report Viewer
                </span>'''
            )

            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            shutil.copy2(src_path, dest_path)

    shutil.copytree(src_static, static_dir, dirs_exist_ok=True)

    # Write reader app.py
    app_py = os.path.join(reader_dir, 'app.py')
    with open(app_py, 'w', encoding='utf-8') as f:
        f.write("""
import os
import json
import time
import threading
import webbrowser
from flask import Flask, render_template, jsonify, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))

def open_browser(url: str, delay: float = 1.5) -> None:
    def delayed_open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
            print(f"Opened browser to: {url}")
        except Exception as e:
            print(f"Could not open browser: {e}")

    thread = threading.Thread(target=delayed_open)
    thread.daemon = True
    thread.start()

def find_available_port(start_port: int = 5050, max_attempts: int = 10) -> int:
    \"\"\"Find an available port starting from start_port\"\"\"
    for port in range(start_port, start_port + max_attempts):
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return start_port  # Fallback to original port

def _load(path):
    with open(os.path.join(BASE_DIR, 'data', path), 'r', encoding='utf-8') as f:
        return json.load(f)

@app.route('/')
def index():
    meta = _load('meta.json')
    project_name = meta.get('project_name', '')
    if project_name:
        # Auto-navigate to the report dashboard for this project
        return report_dashboard(project_name)
    return render_template('report_dashboard.html', **meta)

@app.route('/report/<project_name>')
def report_dashboard(project_name):
    meta = _load('meta.json')
    return render_template('report_dashboard.html', **meta)

@app.route('/report/<project_name>/<page>')
def report_page(project_name, page):
    if page not in ['indicators', 'files', 'geographic', 'security', 'technical']:
        abort(404)
    meta = _load('meta.json')
    return render_template(f'report_{page}.html', **meta)

@app.route('/splash')
def splash():
    \"\"\"Redirect to main report dashboard\"\"\"
    meta = _load('meta.json')
    project_name = meta.get('project_name', '')
    return report_dashboard(project_name) if project_name else index()

@app.route('/home')
@app.route('/dashboard')
def home():
    \"\"\"Redirect to main report dashboard\"\"\"
    return index()

@app.route('/api/report/<project_name>/<data_type>')
def api_report_data(project_name, data_type):
    if data_type not in ['indicators', 'files', 'geographic', 'security', 'technical']:
        return jsonify({\"success\": False, \"error\": \"Invalid data type\"})
    data = _load(f\"{data_type}.json\")
    return jsonify({\"success\": True, **data})

if __name__ == '__main__':
    # Find an available port
    port = find_available_port(5050, 10)
    url = f\"http://127.0.0.1:{port}\"

    # Auto-open browser when starting
    print(f\"Starting report viewer on {url}\")
    print(\"The report will automatically open in your browser...\")
    open_browser(url)

    app.run(host='127.0.0.1', port=port, use_reloader=False)
""".strip()
        )

    # Create run.bat (Windows)
    run_bat = os.path.join(package_dir, 'run.bat')
    with open(run_bat, 'w', encoding='utf-8', newline='\r\n') as f:
        f.write("@echo off\r\n")
        f.write("setlocal\r\n")
        f.write("cd /d %~dp0\r\n")
        f.write("echo Starting Project Revelare Report Viewer...\r\n")
        f.write("echo.\r\n")
        f.write("echo The report will automatically open in your browser.\r\n")
        f.write("echo If it doesn't open, navigate to: http://127.0.0.1:5050\r\n")
        f.write("echo (The server will automatically find an available port if 5050 is busy)\r\n")
        f.write("echo.\r\n")
        f.write("echo Press Ctrl+C to stop the server.\r\n")
        f.write("echo.\r\n")
        f.write("python reader\\app.py\r\n")
        f.write("endlocal\r\n")

    # Zip the package
    zip_path = os.path.join(export_root, f"{package_dir_name}.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, package_dir)
                z.write(full_path, arcname)

    logger.info(f"Report reader package created: {zip_path}")
    return zip_path
