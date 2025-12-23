from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, Response, jsonify
import os
import tempfile
import threading
import json
import sqlite3
import shutil
import csv
import socket
import sys
import time
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator, InputValidator
from revelare.core.case_manager import case_manager
from revelare.core.extractor import run_extraction
from revelare.utils import reporter
import revelare.utils.file_extractor as file_extractor

active_threads = []
shutdown_event = threading.Event()

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'web', 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'web', 'static'))
app.secret_key = Config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
# Remove file size limit - set to None for unlimited uploads
app.config['MAX_CONTENT_LENGTH'] = None

logger = get_logger(__name__)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

@app.errorhandler(413)
def request_entity_too_large(error):
    logger.warning(f"File upload too large: {error}")
    flash("File upload failed: File size exceeds server limit. Please try uploading smaller files or contact administrator.", "error")
    return redirect(request.referrer or url_for('home')), 413

@app.route('/favicon.ico')
def favicon():
    return Response(status=204)

def find_available_port(start_port: int = 5000, max_attempts: int = 100) -> int:
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts - 1}")

def open_browser(url: str, delay: float = 1.5) -> None:
    def delayed_open():
        import webbrowser
        time.sleep(delay)
        try:
            webbrowser.open(url)
            logger.info(f"Opened browser to: {url}")
        except Exception as e:
            logger.error(f"Could not open browser: {e}")
    
    thread = threading.Thread(target=delayed_open)
    thread.daemon = True
    thread.start()

def get_db_connection():
    return sqlite3.connect(Config.DATABASE)

def init_database() -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_value TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                project_name TEXT NOT NULL,
                context TEXT,
                timestamp_str TEXT,
                position INTEGER,
                confidence_score REAL,
                is_relevant INTEGER,
                source_port TEXT,
                destination_port TEXT,
                protocol TEXT,
                user_agent TEXT,
                session_id TEXT,
                UNIQUE(indicator_value, project_name, context) 
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT UNIQUE NOT NULL,
                created_at DATETIME NOT NULL,
                status TEXT DEFAULT 'processing',
                total_files INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                completed_at DATETIME
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators (indicator_value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_project_name ON indicators (project_name)')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

def update_master_database(project_name: str, findings: Dict[str, Dict[str, Any]]) -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR IGNORE INTO projects (project_name, created_at, status, total_findings)
            VALUES (?, ?, ?, ?)
        ''', (project_name, datetime.now().isoformat(), 'processing', 0))
        
        total_inserted = 0
        
        from revelare.utils.data_enhancer import DataEnhancer
        temp_enhancer = DataEnhancer() 
        
        for category, items in findings.items():
            if category == 'Processing_Summary': continue
            
            for value, context in items.items():
                dummy_indicator = temp_enhancer.create_enhanced_indicator(
                    indicator=value, category=category, context=context, file_name="DB_RECONSTRUCT", position=0
                )
                
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO indicators 
                        (indicator_value, indicator_type, project_name, context, timestamp_str, position, confidence_score, is_relevant, source_port, destination_port, protocol, user_agent, session_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        str(value), str(category), str(project_name), str(context),
                        str(dummy_indicator.timestamp), int(dummy_indicator.position) if dummy_indicator.position is not None else 0, 
                        float(dummy_indicator.confidence_score) if dummy_indicator.confidence_score is not None else 0.0, 
                        int(dummy_indicator.is_relevant) if dummy_indicator.is_relevant is not None else 0,
                        str(dummy_indicator.source_port) if dummy_indicator.source_port is not None else None, 
                        str(dummy_indicator.destination_port) if dummy_indicator.destination_port is not None else None, 
                        str(dummy_indicator.protocol) if dummy_indicator.protocol is not None else None,
                        str(dummy_indicator.user_agent) if dummy_indicator.user_agent is not None else None, 
                        str(dummy_indicator.session_id) if dummy_indicator.session_id is not None else None
                    ))
                    
                    if cursor.rowcount > 0: total_inserted += 1
                except Exception as e:
                    logger.warning(f"Failed to insert indicator {value} into DB: {e}")
        
        cursor.execute('''
             UPDATE projects SET status=?, total_findings=?, completed_at=? WHERE project_name=?
        ''', ('completed', total_inserted, datetime.now().isoformat(), project_name))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Database update complete. Inserted {total_inserted} new indicators for {project_name}.")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update database: {e}")
        return False

@app.route('/global_dashboard')
def global_dashboard():
    dashboard_path = os.path.join(Config.UPLOAD_FOLDER, 'index.html')
    if os.path.exists(dashboard_path):
        with open(dashboard_path, 'r', encoding='utf-8') as f:
            return f.read()
    else:
        # Try to generate it on the fly if it doesn't exist
        try:
            from revelare.utils.global_reporter import GlobalReporter
            reporter = GlobalReporter(Config.UPLOAD_FOLDER)
            reporter.generate_dashboard(dashboard_path)
            with open(dashboard_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to generate global dashboard: {e}")
            flash("Global dashboard not yet available. Process some cases first.", "info")
            return redirect(url_for('home'))

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        flash("Please create a case first using the 'Create New Case' button", "info")
        return redirect(url_for('create_case'))

    available_cases = case_manager.get_available_cases()
    db_projects = []

    for case in available_cases:
        db_projects.append({
            'name': case['name'],
            'status': 'completed' if case.get('has_report') else 'processing',
            'findings': case.get('findings_count', 0),
            'report_exists': case.get('has_report', False)
        })

    return render_template('dashboard.html', projects=db_projects)

@app.route('/link_analysis', methods=['GET', 'POST'])
def link_analysis():
    try:
        results = None
        search_term = ""
        
        if request.method == 'POST':
            search_term = request.form.get('indicator', '').strip()
            
            is_valid, error_msg = InputValidator.validate_indicator_search(search_term)
            if not is_valid:
                flash(f"Error: {error_msg}", "error")
                return render_template('link_analysis.html', results=None, search_term=search_term)
            
            if search_term:
                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute(
                    "SELECT DISTINCT project_name FROM indicators WHERE indicator_value = ?",
                    (search_term,)
                )
                direct_links = sorted([row[0] for row in cursor.fetchall()])

                indicators_by_case = defaultdict(set)
                if direct_links:
                    placeholders = ', '.join('?' for _ in direct_links)
                    cursor.execute(
                        f"SELECT project_name, indicator_value FROM indicators WHERE project_name IN ({placeholders})",
                        direct_links
                    )
                    for case, indicator in cursor.fetchall():
                        if indicator != search_term:
                            indicators_by_case[case].add(indicator)
                
                secondary_links = []
                all_shared_indicators = set().union(*indicators_by_case.values())
                
                if all_shared_indicators:
                    placeholders = ', '.join('?' for _ in all_shared_indicators)
                    direct_link_placeholders = ', '.join('?' for _ in direct_links)
                    
                    cursor.execute(
                        f"""
                        SELECT DISTINCT project_name, indicator_value FROM indicators
                        WHERE indicator_value IN ({placeholders})
                        AND project_name NOT IN ({direct_link_placeholders})
                        """,
                        list(all_shared_indicators) + direct_links
                    )
                    
                    secondary_matches = cursor.fetchall()
                    processed_secondary_cases = set()
                    for secondary_case, shared_indicator in secondary_matches:
                        if secondary_case in processed_secondary_cases:
                            continue
                        for direct_case, indicators in indicators_by_case.items():
                            if shared_indicator in indicators:
                                secondary_links.append({
                                    "case": secondary_case,
                                    "connected_to": direct_case,
                                    "reason": shared_indicator
                                })
                                processed_secondary_cases.add(secondary_case)
                                break

                conn.close()

                results = {
                    "search_term": search_term,
                    "direct_links": direct_links,
                    "secondary_links": sorted(secondary_links, key=lambda x: x['case'])
                }
                logger.info(f"Link analysis for '{search_term}': {len(direct_links)} direct, {len(secondary_links)} secondary.")
        
        return render_template('link_analysis.html', results=results, search_term=search_term)
        
    except Exception as e:
        logger.error(f"Error in link_analysis route: {e}", exc_info=True)
        flash("An unexpected error occurred during link analysis", "error")
        return render_template('link_analysis.html', results=None, search_term="")

@app.route('/project/<path:project_path>')
def serve_project_files(project_path):
    if not SecurityValidator.is_safe_path(target_path=os.path.join(Config.UPLOAD_FOLDER, project_path), base_path=Config.UPLOAD_FOLDER):
        abort(403)
    
    full_path = os.path.join(Config.UPLOAD_FOLDER, project_path)
    if not os.path.exists(full_path) or os.path.isdir(full_path):
        abort(404)
    
    return send_from_directory(Config.UPLOAD_FOLDER, project_path, as_attachment=False)

@app.route('/email_browser', methods=['GET'])
def email_browser():
    try:
        cases = case_manager.get_available_cases()
        cases_with_emails = [case for case in cases if case.get('email_archive_count', 0) > 0]
        return render_template('email_browser.html', cases_with_emails=cases_with_emails)
    except Exception as e:
        logger.error(f"Error getting cases for email browser: {e}")
        flash("Failed to load cases with email archives.", "error")
        return render_template('email_browser.html', cases_with_emails=[])
        
@app.route('/inbox/<path:case_name>')
def inbox(case_name):
    return render_template('inbox.html', case_name=case_name)

@app.route('/api/case_emails/<path:case_name>')
def api_case_emails(case_name):
    try:
        from revelare.utils.mbox_viewer import EmailBrowser
    except Exception as e:
        logger.warning(f"Email browser module unavailable: {e}")
        return jsonify({"error": "Email browsing not available on this system."})
    
    browser = EmailBrowser()
    try:
        archives = browser.get_email_archives_in_case(case_name)
        if not archives:
            return jsonify({"error": "No email archives found in this case."})
        
        all_messages = []
        errors = []
        for archive in archives:
            try:
                analysis = browser.analyze_email_archive(archive['path'])
                if analysis and 'messages' in analysis:
                    all_messages.extend(analysis['messages'])
                elif analysis and 'error' in analysis:
                    errors.append(f"{os.path.basename(archive['path'])}: {analysis['error']}")
            except Exception as e:
                logger.warning(f"Error analyzing archive {archive['path']}: {e}")
                errors.append(f"{os.path.basename(archive['path'])}: {str(e)}")
        
        if not all_messages and errors:
            return jsonify({"error": f"Failed to parse email archives. Errors: {'; '.join(errors)}"})
        
        return jsonify({"success": True, "emails": all_messages, "warnings": errors if errors else None})
    except Exception as e:
        logger.error(f"Failed to fetch emails for {case_name}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to load and parse email archives: {str(e)}"})

@app.route('/string_search', methods=['GET', 'POST'])
def string_search():
    try:
        if request.method == 'POST':
            project_name = request.form.get('project_name', '').strip()
            search_strings = request.form.get('search_strings', '').strip()
            use_regex = 'use_regex' in request.form
            
            if not project_name or not search_strings:
                flash("Project name and search strings are required.", "error")
                return redirect(url_for('string_search'))

            project_dir = os.path.join(Config.UPLOAD_FOLDER, project_name)
            if not os.path.isdir(project_dir):
                flash(f"Project '{project_name}' not found.", "error")
                return redirect(url_for('string_search'))

            from revelare.utils.string_search import StringSearchEngine
            search_engine = StringSearchEngine(logger)
            
            search_list = [s.strip() for s in search_strings.split(',')] if not use_regex else [search_strings]
            
            results = search_engine.search_directory(
                project_dir,
                search_list,
                use_regex=use_regex
            )
            
            if not results:
                flash("No matches found.", "info")
                return redirect(url_for('string_search'))

            output_file = f"{project_name}_string_search_{int(time.time())}.csv"
            output_path = os.path.join(project_dir, 'exports', output_file)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            search_engine.save_results_to_csv(results, output_path)

            flash(f"Search complete. {len(results)} matches found. Report saved to project exports.", "success")
            return send_from_directory(os.path.join(project_dir, 'exports'), output_file, as_attachment=True)
        
        projects = case_manager.get_available_cases()
        project_names = [p['name'] for p in projects]
        return render_template('string_search.html', projects=project_names)
        
    except Exception as e:
        logger.error(f"Error in string_search route: {e}")
        flash("An unexpected error occurred during string search.", "error")
        return redirect(url_for('home'))

@app.route('/splash')
def splash():
    return render_template('splash.html')

@app.route('/api/projects')
def api_projects():
    try:
        projects = case_manager.get_available_cases()
        return jsonify({'projects': projects})
    except Exception as e:
        logger.error(f"Error fetching projects via API: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/create_case', methods=['GET', 'POST'])
def create_case():
    if request.method == 'POST':
        case_number = request.form.get('case_number', '').strip()
        incident_type = request.form.get('incident_type', '').strip()
        investigator_name = request.form.get('investigator_name', '').strip()
        agency = request.form.get('agency', '').strip()
        classification = request.form.get('classification', 'Unclassified')

        if not all([case_number, incident_type, investigator_name, agency]):
            flash("All required fields must be filled.", "error")
            return redirect(url_for('create_case'))

        success, message, project_dir = case_manager.create_case_via_onboarding(
            case_number, incident_type, {"name": investigator_name}, {"agency": agency}, {"level": classification}
        )

        if success:
            case_name = os.path.basename(project_dir)
            flash(f"Case '{case_name}' created successfully. Please add evidence files.", "success")
            return redirect(url_for('upload_evidence', case_name=case_name))
        else:
            flash(message, "error")
            return redirect(url_for('create_case'))

    return render_template('create_case.html',
                         incident_types=case_manager.onboard.metadata.INCIDENT_TYPES,
                         agencies=case_manager.onboard.metadata.AGENCIES,
                         classifications=case_manager.onboard.metadata.CLASSIFICATIONS)

def process_case_background(case_name: str, evidence_files: List[str]):
    thread_id = threading.current_thread().ident
    active_threads.append(thread_id)
    logger.info(f"Starting background processing for case: {case_name} (thread {thread_id})")
    try:
        if shutdown_event.is_set():
            logger.info(f"Shutdown requested, aborting processing for {case_name}")
            return
        success, message = case_manager.process_evidence_files(case_name, evidence_files)
        if success:
            logger.info(f"Background processing completed: {message}")
        else:
            logger.error(f"Background processing failed: {message}")
    except Exception as e:
        logger.error(f"Critical error in background processing for {case_name}: {e}")
    finally:
        if thread_id in active_threads:
            active_threads.remove(thread_id)
        logger.info(f"Background processing thread {thread_id} finished")

@app.route('/upload_evidence/<path:case_name>', methods=['GET', 'POST'])
def upload_evidence(case_name):
    if request.method == 'POST':
        try:
            files = request.files.getlist('files')
        except Exception as e:
            logger.error(f"Error reading uploaded files: {e}")
            flash(f"Error reading uploaded files. The file may be too large or corrupted. Error: {str(e)}", "error")
            return redirect(url_for('upload_evidence', case_name=case_name))
            
        if not files or not files[0].filename:
            flash("At least one file must be selected.", "error")
            return redirect(url_for('upload_evidence', case_name=case_name))

        case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
        if not os.path.isdir(case_path):
            flash(f"Case '{case_name}' not found.", "error")
            return redirect(url_for('home'))

        evidence_files = []
        for file in files:
            try:
                safe_filename = SecurityValidator.sanitize_filename(file.filename)
                file_path = os.path.join(case_path, 'evidence', safe_filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Stream large files to disk instead of loading into memory
                file.save(file_path)
                evidence_files.append(file_path)
            except Exception as e:
                logger.error(f"Error saving file {file.filename}: {e}")
                flash(f"Error saving file {file.filename}: {str(e)}", "error")
                continue

        if not evidence_files:
            flash("No files were successfully saved. Please check the file selections and try again.", "error")
            return redirect(url_for('upload_evidence', case_name=case_name))

        thread = threading.Thread(target=process_case_background, args=(case_name, evidence_files))
        thread.daemon = True
        thread.start()
        
        flash(f"Evidence uploaded. Processing has started for '{case_name}' in the background.", "success")
        return redirect(url_for('home'))

    return render_template('upload_evidence.html', case_name=case_name)

@app.route('/add_files/<path:case_name>', methods=['GET', 'POST'])
def add_files(case_name):
    if request.method == 'POST':
        try:
            files = request.files.getlist('files')
        except Exception as e:
            logger.error(f"Error reading uploaded files: {e}")
            flash(f"Error reading uploaded files. The file may be too large or corrupted. Error: {str(e)}", "error")
            return redirect(url_for('add_files', case_name=case_name))
        
        # Validate that files were actually selected
        valid_files = [f for f in files if f and f.filename and f.filename.strip()]
        if not valid_files:
            flash("At least one file must be selected", "error")
            return redirect(url_for('add_files', case_name=case_name))

        case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
        if not os.path.isdir(case_path):
            flash(f"Case '{case_name}' not found", "error")
            return redirect(url_for('home'))

        evidence_files = []
        for file in valid_files:
            try:
                safe_filename = SecurityValidator.sanitize_filename(file.filename)
                if not safe_filename:
                    logger.warning(f"Skipping file with empty or invalid filename: {file.filename}")
                    continue
                    
                file_path = os.path.join(case_path, 'evidence', safe_filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Stream large files to disk instead of loading into memory
                file.save(file_path)
                evidence_files.append(file_path)
                logger.info(f"Saved file: {safe_filename} to {file_path}")
            except Exception as e:
                logger.error(f"Error saving file {file.filename}: {e}")
                flash(f"Error saving file {file.filename}: {str(e)}", "error")
                continue

        if not evidence_files:
            flash("No files were successfully saved. Please check the file selections and try again.", "error")
            return redirect(url_for('add_files', case_name=case_name))

        thread = threading.Thread(target=process_case_background, args=(case_name, evidence_files))
        thread.daemon = True
        thread.start()

        flash(f"Additional files added. Re-processing has started for '{case_name}' in the background.", "success")
        return redirect(url_for('case_management', case_name=case_name))

    return render_template('add_files.html', case_name=case_name)

@app.route('/case_management/<path:case_name>')
def case_management(case_name):
    # Debug logging
    logger.info(f"Case management requested for: '{case_name}'")
    logger.info(f"Upload folder: {Config.UPLOAD_FOLDER}")
    
    # Check if case directory exists
    case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
    logger.info(f"Looking for case at: {case_path}")
    logger.info(f"Case directory exists: {os.path.exists(case_path)}")
    
    tree = case_manager.get_case_directory_tree(case_name)
    if tree is None:
        # List available cases for debugging
        available_cases = []
        if os.path.exists(Config.UPLOAD_FOLDER):
            available_cases = [item for item in os.listdir(Config.UPLOAD_FOLDER) 
                             if os.path.isdir(os.path.join(Config.UPLOAD_FOLDER, item))]
        logger.error(f"Case '{case_name}' not found. Available cases: {available_cases}")
        flash(f"Case '{case_name}' not found. Available cases: {', '.join(available_cases[:5])}", "error")
        return redirect(url_for('home'))
    notes = case_manager.get_case_notes(case_name)
    return render_template('case_management.html', case_name=case_name, tree=tree, notes=notes)

@app.route('/reanalyze_case/<path:case_name>', methods=['POST'])
def reanalyze_case(case_name):
    try:
        evidence_files = case_manager.get_evidence_files_for_case(case_name)
        if not evidence_files:
            flash(f"No evidence files found for case '{case_name}'", "error")
            return redirect(url_for('case_management', case_name=case_name))
        
        # Run reanalysis in background thread
        thread = threading.Thread(target=process_case_background, args=(case_name, evidence_files))
        thread.daemon = True
        thread.start()
        
        flash(f"Re-analysis started in the background for '{case_name}'. This may take some time.", "success")
        return redirect(url_for('case_management', case_name=case_name))
    except Exception as e:
        logger.error(f"Failed to start re-analysis for {case_name}: {e}")
        flash(f"Failed to start re-analysis: {str(e)}", "error")
        return redirect(url_for('case_management', case_name=case_name))

@app.route('/save_case_notes/<path:case_name>', methods=['POST'])
def save_case_notes(case_name):
    case_notes = request.form.get('case_notes', '')
    file_notes_json = request.form.get('file_notes', '{}')
    try:
        file_notes = json.loads(file_notes_json)
    except json.JSONDecodeError:
        file_notes = {}
    
    notes_data = {"case_notes": case_notes, "file_notes": file_notes}
    if case_manager.save_case_notes(case_name, notes_data):
        flash("Notes saved successfully", "success")
    else:
        flash("Failed to save notes", "error")
    return redirect(url_for('case_management', case_name=case_name))

@app.route('/fractal-encryption')
def fractal_encryption():
    return render_template('fractal_encryption.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            # Get all form data
            form_data = request.form.to_dict()
            
            # Read existing .env file if it exists
            env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
            env_vars = {}
            
            if os.path.exists(env_file):
                with open(env_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            env_vars[key] = value
            
            # Update with form data
            for key, value in form_data.items():
                if value:  # Only update non-empty values
                    env_vars[key] = value
            
            # Write back to .env file
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write("# Project Revelare - Environment Configuration\n")
                f.write("# Generated automatically from web interface\n\n")
                
                # Core settings
                f.write("# Core Application Settings\n")
                f.write(f"REVELARE_SECRET_KEY={env_vars.get('REVELARE_SECRET_KEY', 'revelare_v7_link_analysis_secure_key_2024')}\n")
                f.write(f"REVELARE_DEBUG={env_vars.get('REVELARE_DEBUG', 'False')}\n")
                f.write(f"REVELARE_HOST={env_vars.get('REVELARE_HOST', '127.0.0.1')}\n")
                f.write(f"REVELARE_PORT={env_vars.get('REVELARE_PORT', '5000')}\n")
                f.write(f"REVELARE_MAX_FILE_SIZE={env_vars.get('REVELARE_MAX_FILE_SIZE', '2048')}\n")
                f.write(f"REVELARE_BINARY_CHUNK_SIZE={env_vars.get('REVELARE_BINARY_CHUNK_SIZE', '8192')}\n")
                f.write(f"REVELARE_LOG_LEVEL={env_vars.get('REVELARE_LOG_LEVEL', 'INFO')}\n\n")
                
                # Database
                f.write("# Database\n")
                f.write(f"REVELARE_DATABASE={env_vars.get('REVELARE_DATABASE', 'logs/revelare_master.db')}\n\n")
                
                # Upload folder
                f.write("# Upload Folder\n")
                f.write(f"REVELARE_UPLOAD_FOLDER={env_vars.get('REVELARE_UPLOAD_FOLDER', 'cases')}\n\n")
                
                # API Keys
                f.write("# API Keys\n")
                # Only implemented APIs
                api_keys = [
                    'OPENAI_API_KEY', 'GOOGLE_SPEECH_API_KEY', 'AI_ASSISTANT_API_KEY', 'AI_ASSISTANT_PROVIDER',
                    'IP_API_KEY', 'ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY', 'SHODAN_API_KEY', 'URLSCAN_API_KEY',
                    'BITCOIN_ABUSE_API_KEY', 'CHAINABUSE_API_KEY'
                ]
                
                for key in api_keys:
                    f.write(f"{key}={env_vars.get(key, '')}\n")
                
                f.write("\n# Email Server Configuration\n")
                f.write(f"SMTP_SERVER={env_vars.get('SMTP_SERVER', 'smtp.gmail.com')}\n")
                f.write(f"SMTP_PORT={env_vars.get('SMTP_PORT', '587')}\n")
                f.write(f"SMTP_USERNAME={env_vars.get('SMTP_USERNAME', '')}\n")
                f.write(f"SMTP_PASSWORD={env_vars.get('SMTP_PASSWORD', '')}\n")
            
            flash('Settings saved successfully! Restart the application to apply changes.', 'success')
            return redirect(url_for('settings'))
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            flash(f'Error saving settings: {str(e)}', 'error')
            return redirect(url_for('settings'))
    
    # Load current settings from environment
    current_settings = {}
    for key in dir(Config):
        if not key.startswith('_') and key.isupper():
            current_settings[key] = getattr(Config, key, '')
    
    return render_template('settings_simple.html', current_settings=current_settings)

@app.route('/shutdown', methods=['POST'])
def shutdown():
    logger.info("Server shutdown requested.")
    shutdown_event.set()
    
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        logger.warning("Not running with the Werkzeug Server. Cannot shutdown gracefully.")
        # A more forceful shutdown for development servers
        def delayed_exit():
            time.sleep(1)
            os._exit(0)
        threading.Thread(target=delayed_exit).start()
        return "Server shutting down forcefully..."
    else:
        shutdown_func()
        return "Server is shutting down..."

def get_report_data(project_name):
    project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
    if not os.path.isdir(project_path):
        abort(404)
    
    findings_file = os.path.join(project_path, 'raw_findings.json')
    if not os.path.exists(findings_file):
        return {"error": "Findings file not found."}

    with open(findings_file, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    total_indicators = sum(len(v) for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict))
    files_processed = findings.get("Processing_Summary", {}).get("Total_Files_Processed", 0)
    
    category_counts = {k: len(v) for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict)}
    category_count = len(category_counts)
    top_categories = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:5]

    recent_indicators = []
    count = 0
    for category, items in findings.items():
        if category == 'Processing_Summary': continue
        if isinstance(items, dict):
                for value, context in items.items():
                    if count >= 10: break
                    file_source = "Unknown"
                    if 'File:' in context:
                        file_source = context.split('File:')[1].split('|')[0].strip()
                recent_indicators.append({
                    'category': category, 'value': value, 'file_source': file_source
                })
                
                count += 1
        if count >= 10: break

    # Get list of available exports
    exports_dir = os.path.join(project_path, 'exports')
    available_exports = []
    if os.path.exists(exports_dir):
        for file in os.listdir(exports_dir):
            if file.endswith('.zip'):
                file_path = os.path.join(exports_dir, file)
                try:
                    file_size = os.path.getsize(file_path)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    available_exports.append({
                        'filename': file,
                        'size': file_size,
                        'created': file_time.strftime('%Y-%m-%d %H:%M:%S')
                    })
                except:
                    pass
        # Sort by creation time, newest first
        available_exports.sort(key=lambda x: x['created'], reverse=True)

    return {
        'project_name': project_name,
        'generation_date': datetime.now().isoformat(),
        'total_indicators': total_indicators,
        'files_processed': files_processed,
        'category_count': category_count,
        'top_categories': top_categories,
        'recent_indicators': recent_indicators,
        'available_exports': available_exports
    }

@app.route('/report/<project_name>')
def report_dashboard(project_name):
    data = get_report_data(project_name)
    if "error" in data:
        flash(data["error"], "error")
        return redirect(url_for('home'))
    return render_template('report_dashboard.html', **data)

@app.route('/export/<project_name>', methods=['POST', 'GET'])
def export_report(project_name):
    """Export a portable report package from existing findings without reprocessing"""
    try:
        success, message, export_path = case_manager.export_report_package(project_name)
        
        if success:
            flash(f"Report exported successfully: {os.path.basename(export_path)}", "success")
            # If it's a POST request, return JSON for AJAX
            if request.method == 'POST':
                return jsonify({
                    "success": True,
                    "message": message,
                    "export_path": export_path,
                    "filename": os.path.basename(export_path)
                })
            # Otherwise redirect
            return redirect(url_for('report_dashboard', project_name=project_name))
        else:
            flash(message, "error")
            if request.method == 'POST':
                return jsonify({"success": False, "message": message}), 400
            return redirect(url_for('report_dashboard', project_name=project_name))
    except Exception as e:
        error_msg = f"Export failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        flash(error_msg, "error")
        if request.method == 'POST':
            return jsonify({"success": False, "message": error_msg}), 500
        return redirect(url_for('report_dashboard', project_name=project_name))

@app.route('/clean_findings/<project_name>', methods=['POST', 'GET'])
def clean_findings(project_name):
    """Clean existing findings by re-validating with updated regex patterns"""
    try:
        success, message, stats = case_manager.clean_findings_regex(project_name)
        
        if success:
            flash(f"Findings cleaned: {message}", "success")
            if request.method == 'POST':
                return jsonify({
                    "success": True,
                    "message": message,
                    "stats": stats
                })
            return redirect(url_for('report_dashboard', project_name=project_name))
        else:
            flash(message, "error")
            if request.method == 'POST':
                return jsonify({"success": False, "message": message}), 400
            return redirect(url_for('report_dashboard', project_name=project_name))
    except Exception as e:
        error_msg = f"Clean failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        flash(error_msg, "error")
        if request.method == 'POST':
            return jsonify({"success": False, "message": error_msg}), 500
        return redirect(url_for('report_dashboard', project_name=project_name))

@app.route('/download_export/<project_name>/<filename>')
def download_export(project_name, filename):
    """Download an exported report package"""
    try:
        project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
        exports_dir = os.path.join(project_path, 'exports')
        
        if not os.path.exists(exports_dir):
            abort(404)
        
        # Security: ensure filename doesn't contain path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            abort(400)
        
        return send_from_directory(exports_dir, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading export: {e}")
        abort(404)

@app.route('/report/<project_name>/<page>')
def report_page(project_name, page):
    valid_pages = ['indicators', 'files', 'geographic', 'security', 'technical']
    if page not in valid_pages:
        abort(404)
    data = get_report_data(project_name)
    if "error" in data:
        flash(data["error"], "error")
        return redirect(url_for('home'))
    return render_template(f'report_{page}.html', **data)
    
@app.route('/api/ai_assistant', methods=['POST'])
def ai_assistant():
    """AI Assistant endpoint for intelligent analysis"""
    if not Config.AI_ASSISTANT_API_KEY:
        return jsonify({"success": False, "error": "AI Assistant API key not configured. Please set AI_ASSISTANT_API_KEY in settings."})
    
    try:
        data = request.get_json()
        project_name = data.get('project_name', '')
        user_message = data.get('message', '')
        conversation_history = data.get('conversation_history', [])
        
        if not project_name or not user_message:
            return jsonify({"success": False, "error": "Missing project_name or message"})
        
        # Load case data for context
        project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
        findings_file = os.path.join(project_path, 'raw_findings.json')
        
        case_summary = {}
        if os.path.exists(findings_file):
            with open(findings_file, 'r', encoding='utf-8') as f:
                findings = json.load(f)
                
            # Create summary for AI context
            case_summary = {
                'total_categories': len([k for k in findings.keys() if k != 'Processing_Summary']),
                'categories': {},
                'file_count': findings.get('Processing_Summary', {}).get('files_processed', 0),
                'indicator_count': findings.get('Processing_Summary', {}).get('total_indicators', 0)
            }
            
            for category, items in findings.items():
                if category != 'Processing_Summary' and isinstance(items, dict):
                    case_summary['categories'][category] = len(items)
        
        # Prepare AI prompt
        system_prompt = """You are an expert digital forensics and threat intelligence analyst assistant. 
You help investigators analyze case data, identify patterns, and provide insights about indicators of compromise (IOCs).

When analyzing data:
- Focus on security implications and threat intelligence
- Identify suspicious patterns and connections
- Provide actionable recommendations
- Be concise but thorough
- Use technical terminology appropriately

You have access to case data including indicators, file sources, and metadata."""
        
        # Build context from case summary
        context = f"Case: {project_name}\n"
        context += f"Files Processed: {case_summary.get('file_count', 0)}\n"
        context += f"Total Indicators: {case_summary.get('indicator_count', 0)}\n"
        context += f"Categories Found: {case_summary.get('total_categories', 0)}\n"
        
        if case_summary.get('categories'):
            context += "\nIndicator Categories:\n"
            for cat, count in list(case_summary['categories'].items())[:10]:  # Top 10
                context += f"- {cat}: {count} indicators\n"
        
        # Call AI API based on provider
        provider = getattr(Config, 'AI_ASSISTANT_PROVIDER', 'openai').lower()
        api_key = Config.AI_ASSISTANT_API_KEY
        
        if provider == 'anthropic':
            # Anthropic Claude API
            import requests
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            
            messages = []
            for msg in conversation_history[-5:]:  # Last 5 for context
                messages.append({
                    "role": msg['role'],
                    "content": msg['content']
                })
            messages.append({
                "role": "user",
                "content": f"{context}\n\nUser Question: {user_message}"
            })
            
            payload = {
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 2000,
                "system": system_prompt,
                "messages": messages
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            ai_response = result['content'][0]['text'] if result.get('content') else "No response generated"
            
        elif provider == 'gemini':
            # Google Gemini API
            import requests
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={api_key}"
            headers = {
                "Content-Type": "application/json"
            }
            
            # Build conversation context
            conversation_text = f"System Instructions: {system_prompt}\n\n"
            conversation_text += f"Case Context:\n{context}\n\n"
            
            # Add conversation history
            for msg in conversation_history[-5:]:  # Last 5 for context
                role_label = "User" if msg['role'] == 'user' else "Assistant"
                conversation_text += f"{role_label}: {msg['content']}\n\n"
            
            conversation_text += f"User: {user_message}"
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": conversation_text
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.7,
                    "maxOutputTokens": 2000
                }
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get('candidates') and len(result['candidates']) > 0:
                ai_response = result['candidates'][0]['content']['parts'][0]['text']
            else:
                ai_response = "No response generated"
            
        else:
            # OpenAI API (default)
            import requests
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            messages = [{"role": "system", "content": system_prompt}]
            for msg in conversation_history[-5:]:  # Last 5 for context
                messages.append({
                    "role": msg['role'],
                    "content": msg['content']
                })
            messages.append({
                "role": "user",
                "content": f"{context}\n\nUser Question: {user_message}"
            })
            
            payload = {
                "model": "gpt-4",
                "messages": messages,
                "max_tokens": 2000,
                "temperature": 0.7
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            ai_response = result['choices'][0]['message']['content'] if result.get('choices') else "No response generated"
        
        return jsonify({"success": True, "response": ai_response})
        
    except ImportError:
        return jsonify({"success": False, "error": "requests library required. Install with: pip install requests"})
    except Exception as e:
        logger.error(f"AI Assistant error: {e}")
        return jsonify({"success": False, "error": f"AI service error: {str(e)}"})

@app.route('/api/report/<project_name>/<data_type>')
def api_report_data(project_name, data_type):
    project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
    findings_file = os.path.join(project_path, 'raw_findings.json')
    if not os.path.exists(findings_file):
        return jsonify({"success": False, "error": "Findings not found."})

    with open(findings_file, 'r', encoding='utf-8') as f:
        findings = json.load(f)
        
    data = []
    if data_type == 'indicators':
        for category, items in findings.items():
            if category == 'Processing_Summary' or not isinstance(items, dict): continue
            
            # Handle nested structure for URLs_by_Domain
            if category == 'URLs_by_Domain':
                for domain, urls in items.items():
                    if isinstance(urls, dict):
                        for url, context in urls.items():
                            file_source, position = "Unknown", "N/A"
                            context_str = str(context)
                            if 'File:' in context_str: file_source = context_str.split('File:')[1].split('|')[0].strip()
                            if 'Position:' in context_str: position = context_str.split('Position:')[1].split('|')[0].strip()
                            
                            data.append({
                                'category': category, 'value': url, 'details': context_str, 'file': file_source, 'position': position
                            })
                    else:
                        # Fallback for non-dict values
                        file_source, position = "Unknown", "N/A"
                        context_str = str(urls)
                        if 'File:' in context_str: file_source = context_str.split('File:')[1].split('|')[0].strip()
                        if 'Position:' in context_str: position = context_str.split('Position:')[1].split('|')[0].strip()
                        
                        data.append({
                            'category': category, 'value': domain, 'details': context_str, 'file': file_source, 'position': position
                        })
            else:
                # Handle regular categories
                for value, context in items.items():
                    file_source, position = "Unknown", "N/A"
                    context_str = str(context)
                    if 'File:' in context_str: file_source = context_str.split('File:')[1].split('|')[0].strip()
                    if 'Position:' in context_str: position = context_str.split('Position:')[1].split('|')[0].strip()

                    data.append({
                        'category': category, 'value': value, 'details': context_str, 'file': file_source, 'position': position
                    })
    elif data_type == 'geographic':
        try:
            # Collect ALL IPv4 indicators from findings
            ip_values = []
            ip_contexts = {}  # Store context for each IP
            
            for category, items in findings.items():
                if 'IPv4' in str(category) and isinstance(items, dict):
                    for ip, context in items.items():
                        ip_values.append(ip)
                        if ip not in ip_contexts:
                            ip_contexts[ip] = []
                        ip_contexts[ip].append({
                            'category': category,
                            'context': context,
                            'file': context.split('File:')[1].split('|')[0].strip() if 'File:' in context else 'Unknown'
                        })

            logger.info(f"Found {len(ip_values)} unique IPs for geographic analysis")
            
            # Enrich ALL IPs
            from revelare.utils import reporter as reporter_utils
            report_gen = reporter_utils.ReportGenerator()
            enriched = report_gen.enrich_ips(ip_values)
            logger.info(f"Enriched {len(enriched)} IPs")

            # Build table rows - ensure EVERY IP gets a row
            for ip_with_port in ip_values:
                # Extract base IP for lookup (remove port if present)
                base_ip = ip_with_port.split(':')[0] if ':' in ip_with_port else ip_with_port
                details = enriched.get(base_ip, {})
                
                # Extract location data with fallbacks
                country = details.get('country', 'Unknown')
                city = details.get('city', 'Unknown')
                asn = details.get('asn', details.get('asn_org', details.get('org', 'Unknown')))
                
                # Determine risk level
                error = details.get('error')
                if error:
                    risk = 'Low'
                elif country in {"RU", "CN", "KP", "IR", "UA", "BY"}:
                    risk = 'High'
                elif country in {"US", "GB", "DE", "FR", "CA", "AU", "JP", "KR"}:
                    risk = 'Low'
                else:
                    risk = 'Medium'

                # Count indicators for this IP
                indicators_count = len(ip_contexts.get(ip_with_port, []))
                
                # Get file sources
                files = list(set([ctx['file'] for ctx in ip_contexts.get(ip_with_port, [])]))
                file_sources = ', '.join(files[:3])  # Show first 3 files
                if len(files) > 3:
                    file_sources += f' (+{len(files)-3} more)'

                data.append({
                    'ip': ip_with_port,
                    'country': country,
                    'city': city,
                    'asn': asn,
                    'risk': risk,
                    'indicators': indicators_count,
                    'files': file_sources
                })
                
            logger.info(f"Generated {len(data)} geographic entries")
        except Exception as e:
            logger.error(f"Error generating geographic data for {project_name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            data = []
    elif data_type == 'files':
        # Aggregate basic file summary from findings contexts
        file_map = {}
        for category, items in findings.items():
            if category == 'Processing_Summary' or not isinstance(items, dict):
                continue
            for value, context in items.items():
                src = "Unknown"
                if 'File:' in context:
                    src = context.split('File:')[1].split('|')[0].strip()
                entry = file_map.setdefault(src, { 'name': src, 'type': os.path.splitext(src)[1].lower().lstrip('.'), 'size': 0, 'indicators': 0, 'status': 'normal' })
                entry['indicators'] += 1
        data = list(file_map.values())
    elif data_type == 'security':
        # Synthesize security threats from existing data
        try:
            logger.info(f"Security API called for {project_name}")
            logger.info(f"Findings keys: {list(findings.keys())}")
            
            # Collect all IPv4s for enrichment
            ip_values = []
            for category, items in findings.items():
                if 'IPv4' in str(category) and isinstance(items, dict):
                    ip_values.extend(list(items.keys()))
            
            logger.info(f"Found {len(ip_values)} IPs for security analysis")
            
            # Enrich IPs if we have any
            enriched_ips = {}
            if ip_values:
                try:
                    from revelare.utils.reporter import ReportGenerator
                    report_gen = ReportGenerator()
                    enriched_ips = report_gen.enrich_ips(ip_values)
                    logger.info(f"Enriched {len(enriched_ips)} IPs")
                except Exception as e:
                    logger.warning(f"Failed to enrich IPs for security: {e}")
            
            # Process IPv4s as potential threats with real threat intelligence
            from revelare.utils.threat_intelligence import ThreatIntelligenceService
            ti_service = ThreatIntelligenceService()
            
            for category, items in findings.items():
                if 'IPv4' in str(category) and isinstance(items, dict):
                    logger.info(f"Processing category: {category} with {len(items)} items")
                    for ip, context in items.items():
                        file_source = "Unknown"
                        if 'File:' in context:
                            file_source = context.split('File:')[1].split('|')[0].strip()
                        
                        # Extract base IP for threat intelligence lookup
                        base_ip = ip.split(':')[0] if ':' in ip else ip
                        
                        # Get threat intelligence for this IP
                        threat_data = ti_service.enrich_indicator(base_ip, 'ip')
                        
                        # Determine threat level based on threat intelligence
                        threat_type = "suspicious_ip"
                        severity = "medium"
                        confidence = 60
                        
                        # Check AbuseIPDB data
                        if 'abuseipdb' in threat_data.get('enrichments', {}):
                            abuse_data = threat_data['enrichments']['abuseipdb']
                            abuse_confidence = abuse_data.get('abuse_confidence', 0)
                            total_reports = abuse_data.get('total_reports', 0)
                            
                            if abuse_confidence > 75 or total_reports > 10:
                                threat_type = "malicious_ip"
                                severity = "high"
                                confidence = min(95, 60 + abuse_confidence)
                            elif abuse_confidence > 25 or total_reports > 0:
                                threat_type = "suspicious_ip"
                                severity = "medium"
                                confidence = min(80, 50 + abuse_confidence)
                        
                        # Check Shodan data for additional context
                        if 'shodan' in threat_data.get('enrichments', {}):
                            shodan_data = threat_data['enrichments']['shodan']
                            vulnerabilities = shodan_data.get('vulnerabilities', [])
                            if vulnerabilities:
                                threat_type = "vulnerable_device"
                                severity = "high" if len(vulnerabilities) > 3 else "medium"
                                confidence = min(90, confidence + len(vulnerabilities) * 10)
                        
                        # Fallback to geolocation-based assessment
                        if threat_type == "suspicious_ip" and base_ip in enriched_ips:
                            ip_data = enriched_ips[base_ip]
                            if isinstance(ip_data, dict):
                                country = ip_data.get('country', '')
                                # Higher risk countries
                                if country in {"RU", "CN", "KP", "IR", "UA", "BY"}:
                                    severity = "high"
                                    confidence = 80
                                elif country in {"US", "GB", "DE", "FR", "CA", "AU"}:
                                    severity = "low"
                                    confidence = 40
                                else:
                                    severity = "medium"
                                    confidence = 60
                        
                        data.append({
                            'indicator': ip,
                            'type': threat_type,
                            'severity': severity,
                            'source': file_source,
                            'confidence': confidence,
                            'last_seen': datetime.now().isoformat(),
                            'threat_intel': threat_data.get('enrichments', {})
                        })
            
            # Process URLs as potential threats with VirusTotal
            for category, items in findings.items():
                if category == 'URLs_by_Domain' and isinstance(items, dict):
                    for domain, urls in items.items():
                        if isinstance(urls, dict):
                            for url, context in urls.items():
                                file_source = "Unknown"
                                if 'File:' in context:
                                    file_source = context.split('File:')[1].split('|')[0].strip()
                                
                                # Get threat intelligence for this URL
                                threat_data = ti_service.enrich_indicator(url, 'url')
                                
                                # Determine threat level based on threat intelligence
                                threat_type = "suspicious_url"
                                severity = "low"
                                confidence = 30
                                
                                # Check VirusTotal data
                                if 'virustotal' in threat_data.get('enrichments', {}):
                                    vt_data = threat_data['enrichments']['virustotal']
                                    positives = vt_data.get('positives', 0)
                                    total_scans = vt_data.get('total_scans', 0)
                                    
                                    if positives > 0:
                                        threat_type = "malware"
                                        severity = "high" if positives > 5 else "medium"
                                        confidence = min(95, 70 + (positives / total_scans * 100))
                                    else:
                                        threat_type = "clean_url"
                                        severity = "low"
                                        confidence = 20
                                
                                # Fallback to pattern-based assessment
                                if threat_type == "suspicious_url":
                                    url_lower = url.lower()
                                    if any(suspicious in url_lower for suspicious in ['phishing', 'malware', 'virus', 'trojan', 'botnet']):
                                        threat_type = "malware"
                                        severity = "high"
                                        confidence = 85
                                    elif any(suspicious in url_lower for suspicious in ['bit.ly', 'tinyurl', 't.co', 'goo.gl']):
                                        threat_type = "suspicious_url"
                                        severity = "medium"
                                        confidence = 60
                                    elif any(suspicious in url_lower for suspicious in ['.tk', '.ml', '.ga', '.cf']):
                                        threat_type = "suspicious_url"
                                        severity = "medium"
                                        confidence = 70
                                
                                data.append({
                                    'indicator': url,
                                    'type': threat_type,
                                    'severity': severity,
                                    'source': file_source,
                                    'confidence': confidence,
                                    'last_seen': datetime.now().isoformat(),
                                    'threat_intel': threat_data.get('enrichments', {})
                                })
            
            # Process other potentially suspicious indicators
            suspicious_categories = ['Email_Addresses', 'Phone_Numbers', 'Credit_Cards', 'SSN']
            for category, items in findings.items():
                if category in suspicious_categories and isinstance(items, dict):
                        for value, context in items.items():
                            file_source = "Unknown"
                        if 'File:' in context:
                            file_source = context.split('File:')[1].split('|')[0].strip()
                        
                        threat_type = "data_exposure"
                        severity = "high" if category in ['Credit_Cards', 'SSN'] else "medium"
                        confidence = 90 if category in ['Credit_Cards', 'SSN'] else 70
                        
                        data.append({
                            'indicator': value,
                            'type': threat_type,
                            'severity': severity,
                            'source': file_source,
                            'confidence': confidence,
                            'last_seen': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"Error generating security data for {project_name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            data = []
    elif data_type == 'technical':
        # Provide a generic dump of categories with counts as a placeholder
        for category, items in findings.items():
            if category == 'Processing_Summary' or not isinstance(items, dict):
                continue
            data.append({ 'category': category, 'count': len(items) })
    
    return jsonify({"success": True, data_type: data})

def launch_web_app():
    if not init_database():
        print("[ERROR] Failed to initialize database. Exiting.")
        return
    
    try:
        port = find_available_port(Config.PORT)
        url = f"http://{Config.HOST}:{port}"
        print(f"Starting server on {url}")
        open_browser(url)
        app.run(host=Config.HOST, port=port, debug=Config.DEBUG, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to launch web app: {e}")

if __name__ == '__main__':
    launch_web_app()
