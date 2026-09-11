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
from revelare.core.database import get_db_connection, init_database, update_master_database
from revelare.core.money_pathways import link_analysis_sql_filter
from revelare.core.extractor import run_extraction
from revelare.core.findings_store import (
    count_findings,
    load_findings,
    parse_indicator_context,
)
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
        is_done = case.get('is_complete') or case.get('has_report') or case.get('findings_count', 0) > 0
        db_projects.append({
            'name': case['name'],
            'status': 'completed' if is_done else 'processing',
            'findings': case.get('findings_count', 0),
            'report_exists': is_done
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
                type_clause, type_params = link_analysis_sql_filter()

                cursor.execute(
                    "SELECT DISTINCT project_name FROM indicators "
                    "WHERE indicator_value = ? AND %s" % type_clause,
                    [search_term] + type_params
                )
                direct_links = sorted([row[0] for row in cursor.fetchall()])

                indicators_by_case = defaultdict(set)
                if direct_links:
                    placeholders = ', '.join('?' for _ in direct_links)
                    cursor.execute(
                        "SELECT project_name, indicator_value FROM indicators "
                        "WHERE project_name IN (%s) AND %s" % (placeholders, type_clause),
                        list(direct_links) + type_params
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
                        """
                        SELECT DISTINCT project_name, indicator_value FROM indicators
                        WHERE indicator_value IN (%s)
                        AND project_name NOT IN (%s)
                        AND %s
                        """ % (placeholders, direct_link_placeholders, type_clause),
                        list(all_shared_indicators) + list(direct_links) + type_params
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
                         case_tags=case_manager.onboard.metadata.CASE_TAGS,
                         agencies=case_manager.onboard.metadata.AGENCIES,
                         classifications=case_manager.onboard.metadata.CLASSIFICATIONS)

def process_case_background(case_name: str, evidence_files: List[str],
                            audit_sources: Optional[Dict[str, str]] = None,
                            staging_dir: Optional[str] = None,
                            origin: str = "local_path"):
    thread_id = threading.current_thread().ident
    active_threads.append(thread_id)
    logger.info(f"Starting background processing for case: {case_name} (thread {thread_id})")
    try:
        if shutdown_event.is_set():
            logger.info(f"Shutdown requested, aborting processing for {case_name}")
            return
        success, message = case_manager.process_evidence_files(
            case_name, evidence_files, audit_sources=audit_sources, origin=origin
        )
        if success:
            logger.info(f"Background processing completed: {message}")
        else:
            logger.error(f"Background processing failed: {message}")
    except Exception as e:
        logger.error(f"Critical error in background processing for {case_name}: {e}")
    finally:
        if staging_dir:
            file_extractor.cleanup_temp_files(staging_dir)
        if thread_id in active_threads:
            active_threads.remove(thread_id)
        logger.info(f"Background processing thread {thread_id} finished")

def _stage_web_uploads(files, case_name: str) -> Tuple[List[str], Dict[str, str], str]:
    """Save browser uploads to a temp dir for processing. Do not keep a vault copy."""
    from revelare.utils.file_extractor import mkdtemp_in_script_dir
    from revelare.core.source_ingest import UPLOAD_SCHEME
    staging_dir = mkdtemp_in_script_dir(prefix=f"revelare_upload_{case_name}_")
    evidence_files = []
    audit_sources = {}
    for file in files:
        try:
            original_name = file.filename or "upload.bin"
            safe_filename = SecurityValidator.sanitize_filename(original_name)
            if not safe_filename:
                logger.warning(f"Skipping file with empty or invalid filename: {file.filename}")
                continue
            file_path = os.path.join(staging_dir, safe_filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)
            evidence_files.append(file_path)
            audit_sources[file_path] = UPLOAD_SCHEME + original_name
            logger.info(f"Staged upload for processing: {original_name}")
        except Exception as e:
            logger.error(f"Error staging file {getattr(file, 'filename', '?')}: {e}")
            continue
    if not evidence_files:
        file_extractor.cleanup_temp_files(staging_dir)
        return [], {}, ""
    return evidence_files, audit_sources, staging_dir

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

        evidence_files, audit_sources, staging_dir = _stage_web_uploads(files, case_name)

        if not evidence_files:
            flash("No files were successfully saved. Please check the file selections and try again.", "error")
            return redirect(url_for('upload_evidence', case_name=case_name))

        thread = threading.Thread(
            target=process_case_background,
            args=(case_name, evidence_files),
            kwargs={"audit_sources": audit_sources, "staging_dir": staging_dir, "origin": "web_upload"},
        )
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

        evidence_files, audit_sources, staging_dir = _stage_web_uploads(valid_files, case_name)

        if not evidence_files:
            flash("No files were successfully saved. Please check the file selections and try again.", "error")
            return redirect(url_for('add_files', case_name=case_name))

        thread = threading.Thread(
            target=process_case_background,
            args=(case_name, evidence_files),
            kwargs={"audit_sources": audit_sources, "staging_dir": staging_dir, "origin": "web_upload"},
        )
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

def _sync_findings_db(project_name, findings):
    """Load CLI-produced findings into SQLite if the case is missing or still processing."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT status, total_findings FROM projects WHERE project_name=?",
            (project_name,),
        )
        row = cursor.fetchone()
        conn.close()
        if row and row[0] == "completed" and (row[1] or 0) > 0:
            return
        update_master_database(project_name, findings)
    except Exception as exc:
        logger.warning("Could not sync findings DB for %s: %s", project_name, exc)


def get_report_data(project_name):
    project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
    if not os.path.isdir(project_path):
        abort(404)
    
    findings = load_findings(project_path)
    if findings is None:
        return {"error": "Findings file not found."}

    _sync_findings_db(project_name, findings)

    total_indicators = count_findings(findings)
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
                if count >= 10:
                    break
                parsed = parse_indicator_context(context)
                recent_indicators.append({
                    'category': category, 'value': value, 'file_source': parsed['file']
                })
                count += 1
        if count >= 10:
            break

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
        findings = load_findings(project_path)
        
        case_summary = {}
        if findings is not None:
                
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

@app.route('/case_sync', methods=['GET', 'POST'])
def case_sync():
    """Case synchronization interface"""
    from revelare.utils.unified_manager import UnifiedCaseManager
    
    if request.method == 'POST':
        external_dir = request.form.get('external_dir', r'E:\Cases')
        process_files = request.form.get('process_files') == 'on'
        check_duplicates = request.form.get('check_duplicates') == 'on'
        check_cross_case = request.form.get('check_cross_case') == 'on'
        
        try:
            manager = UnifiedCaseManager(external_dir)
            results = manager.run_full_sync(
                process_files=process_files,
                check_duplicates=check_duplicates,
                check_cross_case_duplicates=check_cross_case,
                convert_to_truleo=False
            )
            
            flash(f"Sync complete: {results['sync_stats'].get('cases_discovered', 0)} cases discovered, "
                  f"{results['sync_stats'].get('cases_created', 0)} created, "
                  f"{results['sync_stats'].get('files_processed', 0)} files processed", "success")
            
            if results.get('duplicate_report') and results['duplicate_report'].get('duplicate_groups', 0) > 0:
                flash(f"Found {results['duplicate_report']['duplicate_groups']} duplicate file groups - see report", "warning")
            
            return redirect(url_for('case_sync'))
        except Exception as e:
            flash(f"Sync failed: {str(e)}", "error")
            logger.error(f"Case sync failed: {e}", exc_info=True)
    
    # Get recent sync stats if available
    sync_stats = {}
    duplicate_report = None
    try:
        from revelare.utils.file_deduplication import find_cross_case_duplicates
        duplicates = find_cross_case_duplicates(Path(Config.UPLOAD_FOLDER))
        if duplicates:
            duplicate_report = {
                'groups': len(duplicates),
                'file': str(Path(Config.UPLOAD_FOLDER) / 'duplicate_report.txt')
            }
    except Exception:
        pass
    
    return render_template('case_sync.html', sync_stats=sync_stats, duplicate_report=duplicate_report)

@app.route('/check_duplicates', methods=['POST'])
def check_duplicates():
    """Check for cross-case duplicates"""
    from revelare.utils.file_deduplication import find_cross_case_duplicates, format_duplicate_report
    from pathlib import Path
    
    try:
        duplicates = find_cross_case_duplicates(Path(Config.UPLOAD_FOLDER))
        if duplicates:
            report = format_duplicate_report(duplicates)
            report_file = Path(Config.UPLOAD_FOLDER) / f"duplicate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"Duplicate Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(report)
            
            flash(f"Found {len(duplicates)} duplicate file groups. Report saved to {report_file.name}", "warning")
        else:
            flash("No cross-case duplicates found", "success")
    except Exception as e:
        flash(f"Duplicate check failed: {str(e)}", "error")
        logger.error(f"Duplicate check failed: {e}", exc_info=True)
    
    return redirect(url_for('case_sync'))

@app.route('/convert_truleo/<path:case_name>', methods=['POST'])
def convert_truleo(case_name):
    """Convert case files to Truleo format"""
    from revelare.utils.truleo_converter import convert_case_for_truleo
    
    try:
        result = convert_case_for_truleo(case_name)
        if result.get('success'):
            flash(f"Conversion complete: {result.get('converted', 0)} files converted, "
                  f"{result.get('failed', 0)} failed", "success")
        else:
            flash(f"Conversion failed: {result.get('error', 'Unknown error')}", "error")
    except Exception as e:
        flash(f"Conversion failed: {str(e)}", "error")
        logger.error(f"Truleo conversion failed: {e}", exc_info=True)
    
    return redirect(url_for('case_management', case_name=case_name))

@app.route('/export_case/<path:case_name>', methods=['POST', 'GET'])
def export_case(case_name):
    """Export a case in standardized format (full or indicators-only)"""
    from revelare.utils.case_import_export import CaseExporter
    
    try:
        include_files = request.form.get('include_files', 'true').lower() == 'true'
        include_extracted = request.form.get('include_extracted', 'true').lower() == 'true'
        
        # Default export location
        exports_dir = os.path.join(Config.UPLOAD_FOLDER, case_name, 'exports')
        os.makedirs(exports_dir, exist_ok=True)
        
        exporter = CaseExporter()
        success, message, export_path = exporter.export_case(
            case_name, 
            exports_dir,
            include_files=include_files,
            include_extracted=include_extracted
        )
        
        if success:
            filename = os.path.basename(export_path)
            flash(f"Case exported successfully: {filename}", "success")
            if request.method == 'POST':
                return jsonify({
                    "success": True,
                    "message": message,
                    "export_path": export_path,
                    "filename": filename
                })
            return redirect(url_for('case_management', case_name=case_name))
        else:
            flash(message, "error")
            if request.method == 'POST':
                return jsonify({"success": False, "message": message}), 400
            return redirect(url_for('case_management', case_name=case_name))
    except Exception as e:
        error_msg = f"Export failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        flash(error_msg, "error")
        if request.method == 'POST':
            return jsonify({"success": False, "message": error_msg}), 500
        return redirect(url_for('case_management', case_name=case_name))

@app.route('/import_case', methods=['GET', 'POST'])
def import_case():
    """Import a case from an exported zip file"""
    from revelare.utils.case_import_export import CaseImporter
    
    if request.method == 'GET':
        return render_template('import_case.html')
    
    try:
        if 'export_file' not in request.files:
            flash("No file provided", "error")
            return redirect(url_for('import_case'))
        
        file = request.files['export_file']
        if file.filename == '':
            flash("No file selected", "error")
            return redirect(url_for('import_case'))
        
        if not file.filename.endswith('.zip'):
            flash("Export file must be a .zip file", "error")
            return redirect(url_for('import_case'))
        
        # Save uploaded file temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            target_case_name = request.form.get('case_name', '').strip() or None
            overwrite = request.form.get('overwrite', 'false').lower() == 'true'
            
            importer = CaseImporter()
            success, message, case_path = importer.import_case(
                tmp_path,
                target_case_name=target_case_name,
                overwrite=overwrite
            )
            
            if success:
                case_name = os.path.basename(case_path)
                flash(f"Case '{case_name}' imported successfully", "success")
                return redirect(url_for('case_management', case_name=case_name))
            else:
                flash(message, "error")
                return redirect(url_for('import_case'))
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except:
                pass
                
    except Exception as e:
        error_msg = f"Import failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        flash(error_msg, "error")
        return redirect(url_for('import_case'))

@app.route('/download_case_export/<path:case_name>/<filename>')
def download_case_export(case_name, filename):
    """Download an exported case file"""
    try:
        exports_dir = os.path.join(Config.UPLOAD_FOLDER, case_name, 'exports')
        
        if not os.path.exists(exports_dir):
            abort(404)
        
        # Security: ensure filename doesn't contain path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            abort(400)
        
        return send_from_directory(exports_dir, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading case export: {e}")
        abort(404)

@app.route('/api/report/<project_name>/<data_type>')
def api_report_data(project_name, data_type):
    project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
    findings = load_findings(project_path)
    if findings is None:
        return jsonify({"success": False, "error": "Findings not found."})
    _sync_findings_db(project_name, findings)
        
    data = []
    if data_type == 'indicators':
        for category, items in findings.items():
            if category == 'Processing_Summary' or not isinstance(items, dict): continue
            
            # Handle nested structure for URLs_by_Domain
            if category == 'URLs_by_Domain':
                for domain, urls in items.items():
                    if isinstance(urls, dict):
                        for url, context in urls.items():
                            parsed = parse_indicator_context(context)
                            data.append({
                                'category': category, 'value': url, 'details': parsed['details'],
                                'file': parsed['file'], 'position': parsed['position'],
                                'source_path': parsed['source_path'], 'source_hash': parsed['source_hash']
                            })
                    else:
                        parsed = parse_indicator_context(urls)
                        data.append({
                            'category': category, 'value': domain, 'details': parsed['details'],
                            'file': parsed['file'], 'position': parsed['position'],
                            'source_path': parsed['source_path'], 'source_hash': parsed['source_hash']
                        })
            else:
                for value, context in items.items():
                    parsed = parse_indicator_context(context)
                    data.append({
                        'category': category, 'value': value, 'details': parsed['details'],
                        'file': parsed['file'], 'position': parsed['position'],
                        'source_path': parsed['source_path'], 'source_hash': parsed['source_hash']
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
            suspicious_categories = [
                'Email_Addresses', 'Phone_Numbers', 'Credit_Cards',
                'Credit_Card_Numbers', 'SSN'
            ]
            for category, items in findings.items():
                if category in suspicious_categories and isinstance(items, dict):
                    for value, context in items.items():
                        file_source = "Unknown"
                        if 'File:' in context:
                            file_source = context.split('File:')[1].split('|')[0].strip()

                        threat_type = "data_exposure"
                        severity = "high" if category in ['Credit_Cards', 'Credit_Card_Numbers', 'SSN'] else "medium"
                        confidence = 90 if category in ['Credit_Cards', 'Credit_Card_Numbers', 'SSN'] else 70

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


@app.route('/corpus_export', methods=['GET'])
def corpus_export_page():
    """Cross-case identifier corpus export builder."""
    try:
        from revelare.utils.corpus_exporter import CorpusExporter, PRIMARY_CASE

        exporter = CorpusExporter()
        cases = exporter.discover_cases()
        identifier_types = exporter.get_available_identifier_types()
        filter_options = collect_filter_options(cases)

        return render_template(
            'corpus_export.html',
            cases=cases,
            identifier_types=identifier_types,
            primary_case=PRIMARY_CASE,
            incident_types=filter_options["incident_types"],
            case_tag_options=filter_options["case_tags"],
            default_columns=[
                t for t in identifier_types if t not in (PRIMARY_CASE,)
            ][:12],
        )
    except Exception as exc:
        logger.error("Corpus export page failed: %s", exc, exc_info=True)
        flash("Failed to load corpus export page.", "error")
        return redirect(url_for('home'))


@app.route('/api/corpus/preview', methods=['POST'])
def api_corpus_preview():
    """Preview corpus rows before export."""
    try:
        from revelare.utils.corpus_exporter import CorpusExporter

        payload = request.get_json(silent=True) or {}
        case_names = payload.get('cases', [])
        primary_key = payload.get('primary_key', '__case__')
        column_types = payload.get('column_types', [])
        include_cross_links = payload.get('include_cross_links', True)

        if not case_names:
            return jsonify({"success": False, "error": "Select at least one case."}), 400

        exporter = CorpusExporter()
        corpus = exporter.build_export_bundle(
            case_names=case_names,
            primary_key=primary_key,
            column_types=column_types,
            include_cross_links=include_cross_links,
        )

        preview_subjects = corpus['subjects'][:50]
        preview_connections = corpus['connections'][:100]
        preview_flat = corpus.get('flat_rows', [])[:100]

        return jsonify({
            "success": True,
            "meta": corpus['meta'],
            "subjects": preview_subjects,
            "connections": preview_connections,
            "flat_rows": preview_flat,
            "cross_links": corpus.get('cross_links', [])[:50],
        })
    except Exception as exc:
        logger.error("Corpus preview failed: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route('/api/corpus/export', methods=['POST'])
def api_corpus_export():
    """Export corpus in CSV bundle, Excel, or JSON format."""
    try:
        from revelare.utils.corpus_exporter import CorpusExporter

        payload = request.get_json(silent=True) or {}
        case_names = payload.get('cases', [])
        primary_key = payload.get('primary_key', '__case__')
        column_types = payload.get('column_types', [])
        export_format = payload.get('format', 'csv').lower()
        include_cross_links = payload.get('include_cross_links', True)

        if not case_names:
            return jsonify({"success": False, "error": "Select at least one case."}), 400

        exporter = CorpusExporter()
        corpus = exporter.build_export_bundle(
            case_names=case_names,
            primary_key=primary_key,
            column_types=column_types,
            include_cross_links=include_cross_links,
        )

        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        case_tag = f"{len(case_names)}cases"

        if export_format == 'json':
            content = exporter.export_json(corpus)
            filename = f"revelare_corpus_{case_tag}_{stamp}.json"
            return Response(
                content,
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment; filename={filename}'},
            )

        if export_format == 'xlsx':
            try:
                content = exporter.export_excel(corpus)
            except RuntimeError as exc:
                return jsonify({"success": False, "error": str(exc)}), 500
            filename = f"revelare_corpus_{case_tag}_{stamp}.xlsx"
            return Response(
                content,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                headers={'Content-Disposition': f'attachment; filename={filename}'},
            )

        if export_format == 'flat_csv':
            content = exporter.export_csv(corpus.get('flat_rows', []))
            filename = f"revelare_identifiers_{case_tag}_{stamp}.csv"
            return Response(
                content,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'},
            )

        content = exporter.export_csv_bundle(corpus)
        filename = f"revelare_corpus_{case_tag}_{stamp}.zip"
        return Response(
            content,
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename={filename}'},
        )

    except Exception as exc:
        logger.error("Corpus export failed: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": str(exc)}), 500


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
