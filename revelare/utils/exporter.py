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
            file_source, position, source_type, device_info = "Unknown", "N/A", "Unknown", ""
            if isinstance(context, str):
                if 'File:' in context:
                    file_source = context.split('File:')[1].split('|')[0].strip()
                if 'Position:' in context:
                    position = context.split('Position:')[1].split('|')[0].strip()
                if 'Source:' in context:
                    source_type = context.split('Source:')[1].split('|')[0].strip()
                if 'Device:' in context:
                    device_info = context.split('Device:')[1].split('|')[0].strip()
                if 'Type:' in context:
                    source_type = context.split('Type:')[1].split('|')[0].strip()
            
            rows.append({
                'category': category,
                'value': value,
                'details': context if isinstance(context, str) else str(context),
                'file': file_source,
                'position': position,
                'source': source_type,
                'device': device_info,
                'category_display': category.replace('_', ' ').title()
            })
    return rows


def _build_geographic(project_name: str, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Collect IPv4s and GPS coordinates
    ip_values: List[str] = []
    gps_coords: List[Dict[str, Any]] = []
    
    for category, items in findings.items():
        if 'IPv4' in str(category) and isinstance(items, dict):
            ip_values.extend(list(items.keys()))
        elif category == 'GPS_Coordinates' and isinstance(items, dict):
            for coord, context in items.items():
                file_source = "Unknown"
                device_info = ""
                if isinstance(context, str):
                    if 'File:' in context:
                        file_source = context.split('File:')[1].split('|')[0].strip()
                    if 'Device:' in context:
                        device_info = context.split('Device:')[1].split('|')[0].strip()
                try:
                    lat, lon = map(str.strip, coord.split(','))
                    gps_coords.append({
                        'latitude': float(lat),
                        'longitude': float(lon),
                        'file': file_source,
                        'device': device_info,
                        'coordinates': coord
                    })
                except:
                    pass

    report_gen = reporter_utils.ReportGenerator()
    enriched = report_gen.enrich_ips(ip_values)

    rows: List[Dict[str, Any]] = []
    
    # Add IP addresses
    for ip, details in enriched.items():
        if not isinstance(details, dict):
            continue
        country = details.get('country') or ''
        region = details.get('region') or ''
        city = details.get('city') or ''
        asn = details.get('as') or details.get('asn') or details.get('asn_org') or details.get('org') or ''
        lat = details.get('lat') or ''
        lon = details.get('lon') or ''
        source = details.get('source') or 'Unknown'
        error = details.get('error')
        
        if error:
            risk = 'Low'
        else:
            risk = 'Medium' if country in {"RU", "CN", "KP", "IR"} else 'Low'

        indicators_count = 0
        file_sources = set()
        for category, items in findings.items():
            if isinstance(items, dict) and 'IPv4' in str(category):
                if ip in items:
                    indicators_count += 1
                    context = items[ip]
                    if isinstance(context, str) and 'File:' in context:
                        file_sources.add(context.split('File:')[1].split('|')[0].strip())

        rows.append({
            'type': 'IP',
            'ip': ip,
            'country': country,
            'region': region,
            'city': city,
            'asn': asn,
            'latitude': lat,
            'longitude': lon,
            'risk': risk,
            'indicators': indicators_count,
            'files': list(file_sources)[:5],  # Limit to first 5 files
            'source': source
        })
    
    # Add GPS coordinates
    for gps in gps_coords:
        rows.append({
            'type': 'GPS',
            'latitude': str(gps['latitude']),
            'longitude': str(gps['longitude']),
            'coordinates': gps['coordinates'],
            'file': gps['file'],
            'device': gps['device'],
            'country': '',
            'city': '',
            'asn': '',
            'risk': 'Low',
            'indicators': 1,
            'files': [gps['file']] if gps['file'] != 'Unknown' else [],
            'source': 'EXIF'
        })
    
    return rows


def _build_files(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    file_map: Dict[str, Dict[str, Any]] = {}
    category_map: Dict[str, set] = {}
    
    for category, items in findings.items():
        if category == 'Processing_Summary' or not isinstance(items, dict):
            continue
        for value, context in items.items():
            src = "Unknown"
            if isinstance(context, str) and 'File:' in context:
                src = context.split('File:')[1].split('|')[0].strip()
            
            entry = file_map.setdefault(src, {
                'name': src,
                'type': os.path.splitext(src)[1].lower().lstrip('.') or 'unknown',
                'size': 0,
                'indicators': 0,
                'categories': set(),
                'status': 'normal'
            })
            entry['indicators'] += 1
            if src not in category_map:
                category_map[src] = set()
            category_map[src].add(category)
    
    # Convert sets to lists for JSON serialization
    for file_name, entry in file_map.items():
        entry['categories'] = sorted(list(category_map.get(file_name, set())))
        entry['category_count'] = len(entry['categories'])
    
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
    processing_summary = findings.get('Processing_Summary', {})
    
    # Add processing summary info
    if processing_summary:
        rows.append({
            'type': 'summary',
            'category': 'Processing Summary',
            'total_files': processing_summary.get('Total_Files_Processed', 0),
            'total_indicators': sum(len(v) for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict)),
            'categories_found': len([k for k in findings.keys() if k != 'Processing_Summary' and isinstance(findings[k], dict)])
        })
    
    # Add category breakdowns
    for category, items in findings.items():
        if category == 'Processing_Summary' or not isinstance(items, dict):
            continue
        
        # Get sample values
        sample_values = list(items.keys())[:3]
        
        rows.append({
            'type': 'category',
            'category': category,
            'category_display': category.replace('_', ' ').title(),
            'count': len(items),
            'sample_values': sample_values
        })
    
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

        if name == 'report_dashboard.html':
            # Create a reader-specific report_dashboard.html that removes export features
            with open(src_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            # Remove export button form section (lines 65-71)
            # Find and remove the div containing the export form
            content = re.sub(
                r'<div>\s*<form method="POST" action="\{\{ url_for\(\'export_report\'.*?</form>\s*</div>',
                '<div></div>',  # Replace with empty div to maintain structure
                content,
                flags=re.DOTALL
            )
            
            # Remove the entire Available Exports section - match from {% if available_exports %} to matching {% endif %}
            # This is tricky because it contains nested {% for %} loops, so we need to count braces
            lines = content.split('\n')
            filtered_lines = []
            skip_export_section = False
            if_count = 0
            
            for line in lines:
                if '{% if available_exports %}' in line:
                    skip_export_section = True
                    if_count = 1
                    continue
                elif skip_export_section:
                    if '{% if' in line:
                        if_count += 1
                    elif '{% endif %}' in line:
                        if_count -= 1
                        if if_count == 0:
                            skip_export_section = False
                    continue
                filtered_lines.append(line)
            
            content = '\n'.join(filtered_lines)
            
            # Remove export-related JavaScript
            content = re.sub(
                r'//\s*Handle export form submission.*?exportBtnText\.textContent = \'Export Report Package\';.*?\}\s*\}\);',
                '',
                content,
                flags=re.DOTALL
            )
            
            # Remove any remaining download_export links
            content = re.sub(
                r'<a href="\{\{ url_for\(\'download_export\'.*?</a>',
                '',
                content,
                flags=re.DOTALL
            )
            
            # Clean up empty divs
            content = re.sub(r'<div>\s*</div>', '', content)
            
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(content)
        elif name == 'base.html':
            # Create a reader-specific base.html that only has routes available in reader app
            reader_base_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Project Revelare Report{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="{{ url_for('index') }}" class="nav-logo">
                <i class="fas fa-search"></i>
                <span>Project Revelare Report</span>
            </a>
            <div class="nav-menu">
                <a href="{{ url_for('index') }}" class="nav-link">
                    <i class="fas fa-home"></i> Dashboard
                </a>
            </div>
        </div>
    </nav>

    <main class="main-content">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="flash flash-{{ category }}">
                            <i class="fas fa-{% if category == 'error' %}exclamation-triangle{% elif category == 'success' %}check-circle{% else %}info-circle{% endif %}"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </main>

    <footer class="footer">
        <p>&copy; 2025 Project Revelare - Digital Forensics and Data Extraction Tool</p>
    </footer>

    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
    {% block scripts %}{% endblock %}
</body>
</html>"""
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(reader_base_html)
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
