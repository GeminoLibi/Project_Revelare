from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, Response
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
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# Email functionality imports
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import imaplib
import email as email_module
from email.header import decode_header

# Import the core logic from our other scripts
from revelare.core.extractor import run_extraction
import revelare.utils.reporter as reporter
import revelare.utils.file_extractor as file_extractor
from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator, InputValidator
from revelare.core.case_manager import case_manager
from revelare.utils.fractal_encryption import FractalEncryption

# --- Configuration ---
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
web_dir = os.path.join(os.path.dirname(current_dir), 'web')

# Global tracking for cleanup
active_threads = []
shutdown_event = threading.Event()
shutdown_requested = False

app = Flask(__name__,
            template_folder=os.path.join(web_dir, 'templates'),
            static_folder=os.path.join(web_dir, 'static'))
app.secret_key = Config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# Initialize logger
logger = get_logger(__name__)

# Global shutdown flag
shutdown_requested = False
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

def find_available_port(start_port: int = 5000, max_attempts: int = 100) -> int:
    """Find the next available port starting from start_port"""
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
    """Open browser with Selenium automation"""
    def delayed_open():
        import time
        time.sleep(delay)
        
        # Try Selenium first
        driver = None
        try:
            logger.info("Attempting to open Chrome with Selenium...")
            
            # Set up Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--window-size=1200,800")
            chrome_options.add_argument("--start-maximized")
            # Remove deprecated experimental options that cause warnings
            chrome_options.add_experimental_option("detach", True)  # Keep browser open
            
            # Try to get Chrome driver
            try:
                driver_path = ChromeDriverManager().install()
                logger.info(f"Chrome driver found at: {driver_path}")
                
                # Fix the path - webdriver_manager sometimes returns a file instead of the executable
                if not driver_path.endswith('.exe'):
                    # Look for the actual chromedriver.exe in the directory
                    import glob
                    exe_files = glob.glob(os.path.join(os.path.dirname(driver_path), "chromedriver*.exe"))
                    if exe_files:
                        driver_path = exe_files[0]
                        logger.info(f"Found actual Chrome driver executable: {driver_path}")
                    else:
                        raise Exception("Chrome driver executable not found")
                
                service = Service(driver_path)
                driver = webdriver.Chrome(service=service, options=chrome_options)
            except Exception as driver_error:
                logger.warning(f"ChromeDriverManager failed: {driver_error}")
                # Try without service (use system PATH)
                driver = webdriver.Chrome(options=chrome_options)
            
            # Navigate to the URL
            driver.get(url)
            logger.info(f"✅ Successfully opened Chrome browser to: {url}")
            
            # Keep the browser open (don't quit immediately)
            # The browser will stay open until the user closes it or the process ends
            
        except Exception as e:
            logger.warning(f"❌ Selenium failed: {e}")
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            
            # Fallback to system default browser
            try:
                logger.info("Falling back to system default browser...")
                import webbrowser
                webbrowser.open(url)
                logger.info(f"✅ Opened fallback browser to: {url}")
            except Exception as fallback_error:
                logger.error(f"❌ Could not open any browser: {fallback_error}")
    
    thread = threading.Thread(target=delayed_open)
    thread.daemon = True
    thread.start()

# Validate configuration
config_errors = Config.validate_config()
if config_errors:
    logger.error(f"Configuration errors: {config_errors}")

# --- Database Management ---
def get_db_connection():
    """Helper to establish a database connection."""
    return sqlite3.connect(Config.DATABASE)

def init_database() -> bool:
    """Creates the master database and table with the full enriched schema."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # NOTE: CRITICAL SCHEMA FIX: Added columns for enriched data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_value TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                project_name TEXT NOT NULL,
                context TEXT,
                
                -- ENRICHED FIELDS (from EnhancedIndicator)
                timestamp_str TEXT,
                position INTEGER,
                confidence_score REAL,
                is_relevant INTEGER, -- 1 or 0
                
                -- NETWORK FIELDS
                source_port TEXT,
                destination_port TEXT,
                protocol TEXT,
                
                -- WEB FIELDS
                user_agent TEXT,
                session_id TEXT,
                
                -- Ensure the core tuple is unique
                UNIQUE(indicator_value, project_name, context) 
            )
        ''')
        
        # Create projects table for better project management
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
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators (indicator_value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators (indicator_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_project_name ON indicators (project_name)')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully with enriched schema")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

def update_master_database(project_name: str, findings: Dict[str, Dict[str, Any]]) -> bool:
    """
    Logs all findings (with full metadata) from a project into the master database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert project status placeholder
        cursor.execute('''
            INSERT OR IGNORE INTO projects (project_name, created_at, status, total_findings)
            VALUES (?, ?, ?, ?)
        ''', (project_name, datetime.now().isoformat(), 'processing', 0))
        
        # Insert indicators
        total_inserted = 0
        total_findings = 0
        
        # Reconstruct the EnhancedIndicator structure by running a dummy enrichment
        from revelare.utils.data_enhancer import DataEnhancer
        temp_enhancer = DataEnhancer() 
        
        for category, items in findings.items():
            if category == 'Processing_Summary': continue
            
            for value, context in items.items():
                total_findings += 1
                
                # REVERSE ENGINEERING METADATA (VULNERABILITY)
                dummy_indicator = temp_enhancer.create_enhanced_indicator(
                    indicator=value, category=category, context=context, file_name="DB_RECONSTRUCT", position=0
                )
                
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO indicators 
                        (indicator_value, indicator_type, project_name, context, timestamp_str, position, confidence_score, is_relevant, source_port, destination_port, protocol, user_agent, session_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        value, category, project_name, context,
                        dummy_indicator.timestamp, dummy_indicator.position, dummy_indicator.confidence_score, dummy_indicator.is_relevant,
                        dummy_indicator.source_port, dummy_indicator.destination_port, dummy_indicator.protocol,
                        dummy_indicator.user_agent, dummy_indicator.session_id
                    ))
                    
                    if cursor.rowcount > 0: total_inserted += 1
                except Exception as e:
                    logger.warning(f"Failed to insert indicator {value} into DB: {e}")
        
        # Final project status update
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

# --- Background Analysis Thread ---
def analysis_thread_worker(extract_path: str, project_path: str, project_name: str) -> None:
    """The background task that runs the full analysis pipeline."""
    try:
        # 1. Extraction (Finds all extracted files in the temp folder)
        temp_files_to_process = [str(p) for p in Path(extract_path).rglob('*') if p.is_file()]
        
        # Change to temp directory for relative path simplicity in extractor.py
        original_cwd = os.getcwd()
        os.chdir(extract_path)
        try:
            findings = run_extraction(temp_files_to_process)
        finally:
            os.chdir(original_cwd)
        
        # 2. Database Update
        update_master_database(project_name, findings)
        
        # 3. File Organization and Cleanup (using hardened file_extractor)
        extracted_files_dir = os.path.join(project_path, "extracted_files")
        Path(extracted_files_dir).mkdir(exist_ok=True)
        
        # Move all processed files from temp folder to final location
        file_extractor.extract_and_rename_files(extract_path, project_name, extracted_files_dir)
        
        # Save raw findings for report generation (required by the web app's export routes)
        with open(os.path.join(project_path, 'raw_findings.json'), 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=4, ensure_ascii=False)
            
        # 4. Report Generation
        ip_addresses = [v for k in findings if 'IPv4' in k for v in findings[k].keys()]
        report_generator = reporter.ReportGenerator()
        enriched_ips = report_generator.enrich_ips(ip_addresses)
        html_report = report_generator.generate_report(project_name, findings, enriched_ips)
        
        # Save HTML Report
        with open(os.path.join(project_path, 'report.html'), 'w', encoding='utf-8') as f:
            f.write(html_report)
            
        # 5. Clean up temporary directory (explicitly delete the folder)
        file_extractor.cleanup_temp_files(extract_path)
        
        logger.info(f"Project '{project_name}' is complete. Report is ready.")
        
    except Exception as e:
        logger.error(f"Critical error in analysis thread for {project_name}: {e}", exc_info=True)
        # Update project status to error
        conn = get_db_connection()
        conn.execute("UPDATE projects SET status=?, completed_at=? WHERE project_name=?", ('error', datetime.now().isoformat(), project_name))
        conn.commit()
        conn.close()
        
        # Attempt cleanup of the temp directory
        file_extractor.cleanup_temp_files(extract_path)
        logger.error(f"Project {project_name} failed. Temporary directory purged.")

# --- Flask Routes ---
@app.route('/', methods=['GET', 'POST'])
def home():
    try:
        if request.method == 'POST':
            # Legacy upload handling - redirect to new case creation flow
            flash("Please create a case first using the 'Create New Case' button", "info")
            return redirect(url_for('create_case'))

        # --- GET Request (Display Dashboard) ---
        available_cases = case_manager.get_available_cases()
        db_projects = []

        for case in available_cases:
            # Map to the expected format for dashboard
            db_projects.append({
                'name': case['name'],
                'status': 'completed' if case.get('has_report') else 'processing',  # Simplified status
                'findings': case.get('findings_count', 0),
                'report_exists': case.get('has_report', False)
            })

        return render_template('dashboard.html', projects=db_projects)

    except Exception as e:
        logger.error(f"Critical error in home route: {e}", exc_info=True)
        flash("An unexpected error occurred", "error")
        return redirect(url_for('home'))

@app.route('/link_analysis', methods=['GET', 'POST'])
def link_analysis():
    # NOTE: FIXED to use the hardened DB connection
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
                    "SELECT DISTINCT project_name FROM indicators WHERE indicator_value = ? ORDER BY project_name",
                    (search_term,)
                )
                results = [row[0] for row in cursor.fetchall()]
                conn.close()
                logger.info(f"Search for '{search_term}' returned {len(results)} results")
        
        return render_template('link_analysis.html', results=results, search_term=search_term)
        
    except Exception as e:
        logger.error(f"Error in link_analysis route: {e}")
        flash("An unexpected error occurred during link analysis", "error")
        return render_template('link_analysis.html', results=None, search_term="")

@app.route('/project/<path:project_path>')
def serve_project_files(project_path):
    """Safely serve project files with security checks"""
    # NOTE: FIXED to use SecurityValidator.is_safe_path
    try:
        # Check 1: Path Traversal
        if not SecurityValidator.is_safe_path(target_path=os.path.join(Config.UPLOAD_FOLDER, project_path), base_path=Config.UPLOAD_FOLDER):
            RevelareLogger.get_logger('security').critical(f"Path Traversal attempt blocked: {project_path}")
            abort(403)
        
        # Check 2: File Existence
        full_path = os.path.join(Config.UPLOAD_FOLDER, project_path)
        if not os.path.exists(full_path) or os.path.isdir(full_path):
            abort(404)
        
        # Check 3: File Type Restriction
        file_ext = os.path.splitext(project_path)[1].lower()
        allowed_exts = ['.html', '.json', '.txt', '.pdf', '.docx', '.xlsx', '.csv'] # Added CSV
        if file_ext not in allowed_exts:
            RevelareLogger.get_logger('security').warning(f"Attempted access to restricted file type: {project_path}")
            abort(403)
        
        # Serve the file from the root folder
        return send_from_directory(Config.UPLOAD_FOLDER, project_path, as_attachment=False)
        
    except Exception as e:
        logger.error(f"Error serving file {project_path}: {e}")
        abort(500)

@app.route('/email_browser', methods=['GET', 'POST'])
def email_browser():
    """Email browser functionality for viewing various email archive formats."""
    try:
        if request.method == 'POST':
            action = request.form.get('action', '')
            email_file = request.form.get('email_file', '').strip()
            case_name = request.form.get('case_name', '')

            if not email_file:
                flash("Error: No email archive specified", "error")
                return redirect(url_for('email_browser'))
            
            # Security validation
            if not SecurityValidator.is_safe_path(email_file):
                flash("Error: Invalid file path", "error")
                return redirect(url_for('email_browser'))

            if not os.path.exists(email_file):
                flash(f"Error: File not found: {email_file}", "error")
                return redirect(url_for('email_browser'))
            
            try:
                from revelare.utils.mbox_viewer import EmailBrowser
                browser = EmailBrowser()

                if action == 'analyze':
                    # Get processing estimate first
                    from revelare.core.file_processors import ArchiveFileProcessor
                    archive_processor = ArchiveFileProcessor()
                    estimate = archive_processor.estimate_processing_time(email_file)

                    # Show warning for large archives
                    if estimate['warning_level'] in ['large', 'huge', 'slow']:
                        flash(estimate['warning_message'], "warning")
                    elif estimate['warning_level'] == 'error':
                        flash(estimate['warning_message'], "error")
                        return redirect(url_for('email_browser'))

                    # Proceed with analysis
                    analysis = browser.analyze_email_archive(email_file)
                    if analysis:
                        # Save analysis to project directory
                        if case_name:
                            project_name = case_name
                        else:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            project_name = f"email_analysis_{timestamp}"

                        safe_project_name = SecurityValidator.sanitize_filename(project_name)
                        project_dir = os.path.join(Config.UPLOAD_FOLDER, safe_project_name)
                        os.makedirs(project_dir, exist_ok=True)

                        # Export analysis
                        json_file = os.path.join(project_dir, "email_analysis.json")
                        with open(json_file, 'w', encoding='utf-8') as f:
                            json.dump(analysis, f, indent=2, ensure_ascii=False)

                        # Generate HTML report if method exists
                        if hasattr(browser, 'generate_html_report'):
                            html_file = os.path.join(project_dir, "email_report.html")
                            browser.generate_html_report(analysis, html_file)

                        message_count = analysis.get('total_messages', 0)
                        format_type = analysis.get('format', 'unknown')
                        processing_note = ""
                        if estimate['estimated_seconds'] > 60:
                            processing_note = f" (Processed in {estimate['time_string']})"

                        flash(f"Email analysis complete: {message_count} messages processed from {format_type.upper()} archive{processing_note}. Results saved to project directory.", "success")
                    else:
                        flash("Error: Email analysis failed", "error")
                
                elif action == 'search':
                    search_terms = request.form.get('search_terms', '').strip()
                    if not search_terms:
                        flash("Error: No search terms provided", "error")
                        return redirect(url_for('email_browser'))

                    terms = [term.strip() for term in search_terms.split(',') if term.strip()]
                    search_fields = request.form.getlist('search_fields')
                    if not search_fields:
                        search_fields = ['subject', 'from', 'to', 'body_text']

                    # For now, search only works with MBOX format
                    email_format = browser.detect_email_format(email_file)
                    if email_format == 'mbox':
                        results = browser.search_messages(email_file, terms, search_fields)
                    else:
                        results = []
                        flash(f"Search not yet supported for {email_format.upper()} format", "warning")
                    
                    if results:
                        # Save search results
                        project_name = request.form.get('project_name', 'mbox_search')
                        safe_project_name = SecurityValidator.sanitize_filename(project_name)
                        project_dir = os.path.join(Config.UPLOAD_FOLDER, safe_project_name)
                        os.makedirs(project_dir, exist_ok=True)
                        
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        csv_file = os.path.join(project_dir, f"mbox_search_{timestamp}.csv")
                        
                        # Export search results
                        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                            fieldnames = ['message_index', 'search_term', 'matched_field', 
                                         'from', 'to', 'subject', 'date']
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            
                            for result in results:
                                msg = result['message_data']
                                writer.writerow({
                                    'message_index': result['message_index'],
                                    'search_term': result['search_term'],
                                    'matched_field': result['matched_field'],
                                    'from': msg['from'],
                                    'to': msg['to'],
                                    'subject': msg['subject'],
                                    'date': msg['date']
                                })
                        
                        flash(f"Email search complete: {len(results)} matches found. Results saved to {os.path.basename(csv_file)}", "success")
                    else:
                        flash("No matches found", "info")

            except Exception as e:
                logger.error(f"Email browser error: {e}")
                flash(f"Email operation failed: {str(e)}", "error")
            
            return redirect(url_for('email_browser'))

        # GET request - show available cases with email archives
        try:
            cases = case_manager.get_available_cases()
            cases_with_emails = [case for case in cases if case.get('email_archive_count', 0) > 0]
        except Exception as e:
            logger.error(f"Error getting cases: {e}")
            cases_with_emails = []

        return render_template('email_browser.html', cases_with_emails=cases_with_emails)

    except Exception as e:
        logger.error(f"Error in email_browser route: {e}")
        flash("An unexpected error occurred during email operation", "error")
        return redirect(url_for('home'))

@app.route('/string_search', methods=['GET', 'POST'])
def string_search():
    """String search functionality for the web interface."""
    try:
        if request.method == 'POST':
            search_strings = request.form.get('search_strings', '').strip()
            project_name = request.form.get('project_name', '').strip()
            context_chars = int(request.form.get('context_chars', 50))
            file_extensions = request.form.get('file_extensions', '').strip()
            
            if not search_strings:
                flash("Error: No search strings provided", "error")
                return redirect(url_for('string_search'))
            
            if not project_name:
                flash("Error: Project name required", "error")
                return redirect(url_for('string_search'))
            
            # Parse search strings (comma-separated)
            search_list = [s.strip() for s in search_strings.split(',') if s.strip()]
            
            # Parse file extensions
            ext_list = []
            if file_extensions:
                ext_list = [ext.strip() for ext in file_extensions.split(',') if ext.strip()]
                ext_list = [ext if ext.startswith('.') else f'.{ext}' for ext in ext_list]
            
            # Get project directory
            project_dir = os.path.join(Config.UPLOAD_FOLDER, project_name)
            if not os.path.exists(project_dir):
                flash(f"Error: Project '{project_name}' not found", "error")
                return redirect(url_for('string_search'))
            
            # Perform string search
            try:
                from revelare.utils.string_search import StringSearchEngine
                
                search_engine = StringSearchEngine(logger)
                results = search_engine.search_directory(
                    project_dir, search_list, context_chars, ext_list
                )
                
                if results:
                    # Save results
                    output_file = os.path.join(project_dir, f"{project_name}_string_search.csv")
                    search_engine.save_results_to_csv(results, output_file)
                    
                    flash(f"String search completed: {len(results)} matches found. Results saved to {os.path.basename(output_file)}", "success")
                else:
                    flash("String search completed: No matches found", "info")
                
            except Exception as e:
                logger.error(f"String search error: {e}")
                flash(f"String search failed: {str(e)}", "error")
            
            return redirect(url_for('string_search'))
        
        # GET request - show string search form
        # Get list of available projects
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT project_name FROM projects ORDER BY created_at DESC")
        projects = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return render_template('string_search.html', projects=projects)
        
    except Exception as e:
        logger.error(f"Error in string_search route: {e}")
        flash("An unexpected error occurred during string search", "error")
        return redirect(url_for('home'))

@app.route('/export/<project_name>/<export_format>')
def export_legal_data(project_name, export_format):
    """Export project data in legal warrant format (JSON or CSV) - pulls from DB."""
    try:
        if export_format not in ['json', 'csv', 'warrant']:
            flash("Invalid export format. Use: json, csv, or warrant", "error")
            return redirect(url_for('home'))
        
        # 1. Data Retrieval (Pulls from the FIXED enriched DB schema)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT indicator_value, indicator_type, context, timestamp_str, source_port, destination_port, protocol, user_agent, confidence_score, position, is_relevant
            FROM indicators 
            WHERE project_name = ? AND is_relevant = 1
        """, (project_name,))
        
        columns = [desc[0] for desc in cursor.description]
        indicator_data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        
        if not indicator_data:
            flash(f"No relevant findings found for project '{project_name}' in the database.", "error")
            return redirect(url_for('home'))
        
        # 2. Export Formatting
        if export_format == 'csv':
            import io
            csv_output = io.StringIO()
            writer = csv.writer(csv_output)
            
            csv_header = ['Project Name', 'Indicator Value', 'Type', 'Confidence', 'Timestamp', 'Position', 'Source Port', 'Destination Port', 'Context']
            writer.writerow(csv_header)
            
            for item in indicator_data:
                writer.writerow([
                    project_name,
                    item['indicator_value'],
                    item['indicator_type'],
                    item['confidence_score'] or '',
                    item['timestamp_str'] or '',
                    item['position'] or '',
                    item['source_port'] or '',
                    item['destination_port'] or '',
                    item['context']
                ])
            
            return Response(csv_output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={project_name}_export.csv'})

        # JSON/WARRANT format
        else:
            warrant_data = {
                "project_name": project_name,
                "export_timestamp": datetime.now().isoformat(),
                "total_indicators": len(indicator_data),
                "indicators": indicator_data
            }
            
            if export_format == 'warrant':
                warrant_data['legal_summary'] = {"time_range": "Available in the database now", "unique_ips": "Available in the database now"} 

            json_data = json.dumps(warrant_data, indent=2, ensure_ascii=False)
            
            return Response(json_data, mimetype='application/json', headers={'Content-Disposition': f'attachment; filename={project_name}_{export_format}_export.json'})
            
    except Exception as e:
        logger.error(f"Error exporting legal data for {project_name}: {e}")
        flash("Error exporting data", "error")
        return redirect(url_for('home'))

def launch_web_app(host=None, port=None, debug=None, open_browser_flag=True):
    """
    Launch the web application with the specified parameters.
    This function can be called from external launchers.
    """
    # Use provided parameters or fall back to config
    host = host or Config.HOST
    port = port or Config.PORT
    debug = debug if debug is not None else Config.DEBUG

    # Initialize database
    if not init_database():
        logger.error("Failed to initialize database. Exiting.")
        return False

    # Find available port
    try:
        available_port = find_available_port(port)
        if available_port != port:
            logger.info(f"Port {port} is in use, using port {available_port} instead")
    except RuntimeError as e:
        logger.error(f"Could not find available port: {e}")
        return False

    # Prepare URL
    base_url = f"http://{host}:{available_port}"
    logger.info(f"Starting Project Revelare v2.4.0 (Web) on {base_url}")

    # Open browser automatically if requested
    if open_browser_flag:
        open_browser(base_url)

    # Start the Flask app
    try:
        logger.info("Starting Flask development server...")
        app.run(host=host, port=available_port, debug=debug, use_reloader=False)
        logger.info("Flask server exited cleanly")
        return True
    except KeyboardInterrupt:
        logger.info("Server shutdown via KeyboardInterrupt")
        return True
    except Exception as e:
        logger.error(f"Failed to start web application: {e}")
        return False

if __name__ == '__main__':
    # Legacy direct execution - use the new launch function
    launch_web_app()

@app.route('/debug')
def debug():
    """Debug page for troubleshooting"""
    return render_template('debug.html')

@app.route('/splash')
def splash():
    """Splash/intro page showcasing the full logo"""
    return render_template('splash.html')

@app.route('/api/projects')
def api_projects():
    """API endpoint to get project status for polling"""
    try:
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT project_name, status, created_at,
                   (SELECT COUNT(*) FROM indicators WHERE project_name = p.project_name) as findings
            FROM projects p
            ORDER BY created_at DESC
        """)

        projects = []
        for row in cursor.fetchall():
            projects.append({
                'name': row[0],
                'status': row[1],
                'created_at': row[2],
                'findings': row[3]
            })

        conn.close()
        return {'projects': projects}
    except Exception as e:
        logger.error(f"Error fetching projects: {e}")
        return {'error': str(e)}, 500

@app.route('/create_case', methods=['GET', 'POST'])
def create_case():
    """Case creation with mandatory onboarding"""
    try:
        if request.method == 'POST':
            # Get form data
            case_number = request.form.get('case_number', '').strip()
            incident_type = request.form.get('incident_type', '').strip()
            investigator_name = request.form.get('investigator_name', '').strip()
            investigator_id = request.form.get('investigator_id', '').strip()
            investigator_email = request.form.get('investigator_email', '').strip()
            agency = request.form.get('agency', '').strip()
            jurisdiction = request.form.get('jurisdiction', '').strip()
            classification = request.form.get('classification', 'Unclassified')

            # Validate required fields
            if not all([case_number, incident_type, investigator_name, agency]):
                flash("All required fields must be filled", "error")
                return redirect(url_for('create_case'))

            # Prepare data for case manager
            investigator_info = {
                "name": investigator_name,
                "id": investigator_id,
                "email": investigator_email
            }

            agency_info = {
                "agency": agency,
                "name": agency,
                "jurisdiction": jurisdiction
            }

            classification_info = {
                "level": classification,
                "retention_period": ""
            }

            # Create case
            success, message, project_dir = case_manager.create_case_via_onboarding(
                case_number, incident_type, investigator_info, agency_info, classification_info
            )

            if success:
                case_name = os.path.basename(project_dir)
                logger.info(f"Case created successfully, redirecting to upload_evidence for case: {case_name}")
                flash(f"Case created successfully: {case_name}", "success")
                return redirect(url_for('upload_evidence', case_name=case_name))
            else:
                flash(message, "error")
                return redirect(url_for('create_case'))

        # GET request - show case creation form
        return render_template('create_case.html',
                             incident_types=case_manager.onboard.metadata.INCIDENT_TYPES,
                             agencies=case_manager.onboard.metadata.AGENCIES,
                             classifications=case_manager.onboard.metadata.CLASSIFICATIONS)

    except Exception as e:
        logger.error(f"Error in create_case: {e}")
        flash("An unexpected error occurred", "error")
        return redirect(url_for('home'))

@app.route('/upload_evidence/<case_name>', methods=['GET', 'POST'])
def upload_evidence(case_name):
    """Upload evidence files for a case"""
    try:
        logger.info(f"upload_evidence called for case: {case_name}, method: {request.method}")

        if request.method == 'POST':
            logger.info(f"POST data received: {dict(request.form)}")
            files = request.files.getlist('files')
            logger.info(f"Files received: {len(files)} files")
            for i, file in enumerate(files):
                logger.info(f"  File {i}: {file.filename} ({file.content_length} bytes)")

            recursive = request.form.get('recursive') == 'on'
            logger.info(f"Recursive processing: {recursive}")

            if not files or not files[0].filename:
                logger.warning("No files selected for upload")
                flash("At least one file must be selected", "error")
                return redirect(url_for('upload_evidence', case_name=case_name))

            # Validate case exists
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            if not os.path.exists(case_path):
                flash(f"Case '{case_name}' not found", "error")
                return redirect(url_for('create_case'))

            # Process files
            evidence_files = []
            for file in files:
                if file.filename:
                    safe_filename = SecurityValidator.sanitize_filename(file.filename)
                    file_path = os.path.join(case_path, 'evidence', safe_filename)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    file.save(file_path)
                    evidence_files.append(file_path)

                    # If recursive processing is enabled and this is a zip, extract it
                    if recursive and safe_filename.lower().endswith(('.zip', '.rar', '.7z')):
                        try:
                            extract_to = os.path.join(case_path, 'evidence', os.path.splitext(safe_filename)[0])
                            os.makedirs(extract_to, exist_ok=True)
                            file_extractor.safe_extract_archive(file_path, extract_to)
                            # Add all extracted files to evidence list
                            for root, dirs, files_in_dir in os.walk(extract_to):
                                for extracted_file in files_in_dir:
                                    evidence_files.append(os.path.join(root, extracted_file))
                        except Exception as extract_error:
                            logger.warning(f"Failed to extract {safe_filename}: {extract_error}")

            if evidence_files:
                # Insert project into database immediately
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO projects (project_name, created_at, status, total_findings)
                        VALUES (?, ?, ?, ?)
                    ''', (case_name, datetime.now().isoformat(), 'processing', 0))
                    conn.commit()
                    conn.close()
                    logger.info(f"Project '{case_name}' inserted into database with status 'processing'")
                except Exception as db_error:
                    logger.error(f"Failed to insert project into database: {db_error}")

                # Start background processing
                logger.info(f"Starting background thread for case: {case_name}")
                thread = threading.Thread(target=process_case_background,
                                        args=(case_name, evidence_files))
                thread.daemon = True
                thread.start()
                logger.info(f"Background thread started for case: {case_name}")

                flash(f"Evidence uploaded and processing started for '{case_name}'", "success")
                return redirect(url_for('home'))

        # GET request - show upload form
        return render_template('upload_evidence.html', case_name=case_name)

    except Exception as e:
        logger.error(f"Error in upload_evidence: {e}")
        flash("An unexpected error occurred", "error")
        return redirect(url_for('home'))

def process_case_background(case_name: str, evidence_files: List[str]):
    """Background processing using unified case manager"""
    thread_id = threading.current_thread().ident
    active_threads.append(thread_id)
    logger.info(f"Starting background processing for case: {case_name} with {len(evidence_files)} files (thread {thread_id})")

    try:
        # Check for shutdown event periodically
        if shutdown_event.is_set():
            logger.info(f"Shutdown requested, aborting background processing for {case_name}")
            return

        logger.info(f"Calling case_manager.process_evidence_files for {case_name}")
        success, message = case_manager.process_evidence_files(case_name, evidence_files)
        logger.info(f"case_manager.process_evidence_files returned: success={success}, message='{message}'")

        if success:
            logger.info(f"Background processing completed successfully: {message}")
        else:
            logger.error(f"Background processing failed: {message}")
    except Exception as e:
        logger.error(f"Critical error in background processing for {case_name}: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    finally:
        # Remove from active threads
        if thread_id in active_threads:
            active_threads.remove(thread_id)
        logger.info(f"Background processing thread {thread_id} finished")

@app.route('/add_files/<case_name>', methods=['GET', 'POST'])
def add_files(case_name):
    """Add additional files to an existing case"""
    try:
        if request.method == 'POST':
            files = request.files.getlist('files')
            recursive = request.form.get('recursive') == 'on'

            if not files or not files[0].filename:
                flash("At least one file must be selected", "error")
                return redirect(url_for('add_files', case_name=case_name))

            # Validate case exists
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            if not os.path.exists(case_path):
                flash(f"Case '{case_name}' not found", "error")
                return redirect(url_for('home'))

            # Process files (similar to upload_evidence but without creating new project record)
            evidence_files = []
            for file in files:
                if file.filename:
                    safe_filename = SecurityValidator.sanitize_filename(file.filename)
                    file_path = os.path.join(case_path, 'evidence', safe_filename)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    file.save(file_path)
                    evidence_files.append(file_path)

                    # If recursive processing is enabled and this is an archive, extract it
                    if recursive and safe_filename.lower().endswith(('.zip', '.rar', '.7z')):
                        try:
                            extract_to = os.path.join(case_path, 'evidence', os.path.splitext(safe_filename)[0])
                            os.makedirs(extract_to, exist_ok=True)
                            file_extractor.safe_extract_archive(file_path, extract_to)
                            # Add all extracted files to evidence list
                            for root, dirs, files_in_dir in os.walk(extract_to):
                                for extracted_file in files_in_dir:
                                    evidence_files.append(os.path.join(root, extracted_file))
                        except Exception as extract_error:
                            logger.warning(f"Failed to extract {safe_filename}: {extract_error}")

            if evidence_files:
                # Start background processing for additional files
                thread = threading.Thread(target=process_additional_files_background,
                                        args=(case_name, evidence_files))
                thread.daemon = True
                thread.start()

                flash(f"Files added and processing started for '{case_name}'", "success")
                return redirect(url_for('case_management', case_name=case_name))

        # GET request - show add files form
        return render_template('add_files.html', case_name=case_name)

    except Exception as e:
        logger.error(f"Error in add_files: {e}")
        flash("An unexpected error occurred", "error")
        return redirect(url_for('home'))

def process_additional_files_background(case_name: str, evidence_files: List[str]):
    """Background processing for additional files added to existing case"""
    try:
        # Process the new files and update the existing case database
        success, message = case_manager.process_evidence_files(case_name, evidence_files)
        if success:
            logger.info(f"Additional files processing completed: {message}")
        else:
            logger.error(f"Additional files processing failed: {message}")
    except Exception as e:
        logger.error(f"Critical error in additional files processing for {case_name}: {e}")

@app.route('/case_management/<path:case_name>')
def case_management(case_name):
    """Case management page with directory browser, re-analysis, and notes"""
    try:
        tree = case_manager.get_case_directory_tree(case_name)
        if tree is None:
            flash(f"Case '{case_name}' not found", "error")
            return redirect(url_for('home'))

        # Get notes for the case
        notes = case_manager.get_case_notes(case_name)

        return render_template('case_management.html', case_name=case_name, tree=tree, notes=notes)

    except Exception as e:
        logger.error(f"Error in case_management: {e}")
        flash("An error occurred while loading case management", "error")
        return redirect(url_for('home'))

@app.route('/reanalyze_case/<path:case_name>', methods=['POST'])
def reanalyze_case(case_name):
    """Re-analyze all evidence files for a case"""
    try:
        logger.info(f"Starting re-analysis for case: {case_name}")

        # Start background re-analysis
        def reanalyze_callback(message):
            logger.info(f"Re-analysis progress: {message}")

        success, message = case_manager.reanalyze_case(case_name, reanalyze_callback)

        if success:
            flash(f"Re-analysis completed: {message}", "success")
        else:
            flash(f"Re-analysis failed: {message}", "error")

        return redirect(url_for('case_management', case_name=case_name))

    except Exception as e:
        logger.error(f"Error in reanalyze_case: {e}")
        flash("An error occurred during re-analysis", "error")
        return redirect(url_for('case_management', case_name=case_name))

@app.route('/save_case_notes/<path:case_name>', methods=['POST'])
def save_case_notes(case_name):
    """Save notes for a case"""
    try:
        case_notes = request.form.get('case_notes', '')
        file_notes_data = request.form.get('file_notes', '{}')

        try:
            file_notes = json.loads(file_notes_data) if file_notes_data else {}
        except json.JSONDecodeError:
            file_notes = {}

        notes_data = {
            "case_notes": case_notes,
            "file_notes": file_notes
        }

        success = case_manager.save_case_notes(case_name, notes_data)

        if success:
            flash("Notes saved successfully", "success")
        else:
            flash("Failed to save notes", "error")

        return redirect(url_for('case_management', case_name=case_name))

    except Exception as e:
        logger.error(f"Error saving case notes: {e}")
        flash("An error occurred while saving notes", "error")
        return redirect(url_for('case_management', case_name=case_name))

# =============================================================================
# EMAIL BROWSER ROUTES (Webmail removed - not needed for local platform)
# =============================================================================

# Processing estimation API
@app.route('/api/estimate_processing', methods=['POST'])
def estimate_processing():
    """Estimate processing time for a file/archive."""
    try:
        data = request.get_json()
        file_path = data.get('file_path', '')

        if not file_path or not SecurityValidator.is_safe_path(file_path):
            return jsonify({'error': 'Invalid file path'}), 400

        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        # Check if it's an email archive
        from revelare.utils.mbox_viewer import EmailBrowser
        browser = EmailBrowser()
        email_format = browser.detect_email_format(file_path)

        if email_format:
            # Use email archive estimation
            from revelare.core.file_processors import ArchiveFileProcessor
            processor = ArchiveFileProcessor()
            estimate = processor.estimate_processing_time(file_path)
        else:
            # For non-email files, provide basic estimate
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024 * 1024)

            # Rough estimate based on file type
            if file_path.lower().endswith(('.zip', '.rar', '.7z', '.tar.gz')):
                processing_rate = 2.0  # Archives are slow
            elif file_path.lower().endswith(('.pdf',)):
                processing_rate = 0.2
            elif file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff')):
                processing_rate = 0.1
            else:
                processing_rate = 0.05  # Default

            estimated_seconds = file_size_mb * processing_rate

            if estimated_seconds < 60:
                time_str = f"{estimated_seconds:.1f} seconds"
            elif estimated_seconds < 3600:
                time_str = f"{estimated_seconds/60:.1f} minutes"
            else:
                time_str = f"{estimated_seconds/3600:.1f} hours"

            estimate = {
                'total_files': 1,
                'total_size_mb': file_size_mb,
                'estimated_seconds': estimated_seconds,
                'time_string': time_str,
                'warning_level': 'slow' if estimated_seconds > 300 else 'normal',
                'warning_message': f'Estimated processing time: {time_str}' if estimated_seconds > 300 else '',
                'file_types': {'unknown': 1}
            }

        return jsonify(estimate)

    except Exception as e:
        logger.error(f"Error estimating processing time: {e}")
        return jsonify({
            'error': str(e),
            'total_files': 0,
            'total_size_mb': 0,
            'estimated_seconds': 0,
            'time_string': 'unknown',
            'warning_level': 'error',
            'warning_message': f'Could not estimate processing time: {str(e)}',
            'file_types': {}
        }), 500
# Webmail functionality completely removed - not needed for local platform

# FRACTAL ENCRYPTION ROUTES
# =============================================================================

@app.route('/fractal-encryption')
def fractal_encryption():
    """Fractal encryption interface"""
    return render_template('fractal_encryption.html')

@app.route('/api/fractal/encrypt', methods=['POST'])
def fractal_encrypt():
    """Encrypt file using fractal encryption"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Get IFS key from request
        ifs_data = request.form.get('ifs_key', '')
        if ifs_data:
            try:
                ifs_transforms = FractalEncryption().get_ifs_from_string(ifs_data)
                encryptor = FractalEncryption(ifs_transforms)
            except Exception as e:
                return jsonify({'error': f'Invalid IFS key: {e}'}), 400
        else:
            encryptor = FractalEncryption()

        # Read file data
        file_data = file.read()

        # Encrypt data
        def progress_callback(progress, status):
            # Could implement WebSocket for real-time progress
            logger.info(f"Fractal encryption: {status}")

        encrypted_data = encryptor.encrypt_data(file_data, file.filename, progress_callback)

        # Generate fractal image
        try:
            image_data = encryptor.create_fractal_image(encrypted_data)
            encrypted_data['image_base64'] = base64.b64encode(image_data).decode('utf-8')
        except ImportError:
            logger.warning("PIL not available for image generation")

        return jsonify({
            'success': True,
            'data': encrypted_data,
            'filename': f"{file.filename}.fractal.json"
        })

    except Exception as e:
        logger.error(f"Fractal encryption error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fractal/decrypt', methods=['POST'])
def fractal_decrypt():
    """Decrypt fractal-encrypted file"""
    try:
        data = request.get_json()
        if not data or 'fractal_data' not in data:
            return jsonify({'error': 'No fractal data provided'}), 400

        fractal_data = data['fractal_data']

        # Get IFS key if provided
        ifs_data = data.get('ifs_key', '')
        if ifs_data:
            try:
                ifs_transforms = FractalEncryption().get_ifs_from_string(ifs_data)
                decryptor = FractalEncryption(ifs_transforms)
            except Exception as e:
                return jsonify({'error': f'Invalid IFS key: {e}'}), 400
        else:
            decryptor = FractalEncryption()

        # Decrypt data
        def progress_callback(progress, status):
            logger.info(f"Fractal decryption: {status}")

        decrypted_bytes, original_filename = decryptor.decrypt_data(fractal_data, progress_callback)

        # Return as base64 for download
        file_base64 = base64.b64encode(decrypted_bytes).decode('utf-8')

        return jsonify({
            'success': True,
            'file_data': file_base64,
            'filename': original_filename,
            'size': len(decrypted_bytes)
        })

    except Exception as e:
        logger.error(f"Fractal decryption error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fractal/generate-image', methods=['POST'])
def fractal_generate_image():
    """Generate fractal image from encrypted data"""
    try:
        data = request.get_json()
        if not data or 'fractal_data' not in data:
            return jsonify({'error': 'No fractal data provided'}), 400

        fractal_data = data['fractal_data']

        # Generate image
        encryptor = FractalEncryption()
        image_data = encryptor.create_fractal_image(fractal_data)

        image_base64 = base64.b64encode(image_data).decode('utf-8')

        return jsonify({
            'success': True,
            'image_base64': image_base64,
            'content_type': 'image/png'
        })

    except ImportError:
        return jsonify({'error': 'Image generation requires Pillow. Install with: pip install Pillow'}), 500
    except Exception as e:
        logger.error(f"Image generation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Shutdown the server with proper cleanup of resources"""
    logger.info(f"Server shutdown requested via web interface. Active threads: {len(active_threads)}")

    try:
        # Set shutdown event to signal background threads
        shutdown_event.set()
        logger.info("Shutdown event set - background threads notified")

        # Wait for active threads to finish (with timeout)
        if active_threads:
            logger.info(f"Waiting for {len(active_threads)} background threads to finish...")
            thread_timeout = 10  # seconds

            start_time = time.time()
            while active_threads and (time.time() - start_time) < thread_timeout:
                time.sleep(0.5)

            if active_threads:
                logger.warning(f"{len(active_threads)} threads still active after timeout")
            else:
                logger.info("All background threads finished cleanly")

        # Close any open database connections
        try:
            # This is a best-effort cleanup - Flask should handle most of this
            logger.info("Database connections will be closed by Flask context")
        except Exception as e:
            logger.warning(f"Error during database cleanup: {e}")

        # Use Flask's shutdown functionality
        shutdown_func = request.environ.get('werkzeug.server.shutdown')
        if shutdown_func is None:
            logger.warning("Werkzeug shutdown function not available - using forced exit")
            # For development server, we need to force exit
            global shutdown_requested
            shutdown_requested = True

            def delayed_exit():
                time.sleep(0.5)  # Give time for response
                logger.info("Shutdown sequence initiated - forcing server exit")
                # Force exit - this is the most reliable way for development servers
                import os
                os._exit(0)

            exit_thread = threading.Thread(target=delayed_exit)
            exit_thread.daemon = True
            exit_thread.start()

            return "Server shutting down...", 200
        else:
            # Proper Werkzeug shutdown
            def delayed_shutdown():
                time.sleep(0.5)  # Brief delay for response
                logger.info("Initiating Flask shutdown via Werkzeug")
                shutdown_func()

            shutdown_thread = threading.Thread(target=delayed_shutdown)
            shutdown_thread.daemon = True
            shutdown_thread.start()

            return "Server shutting down...", 200

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
        return "Error during shutdown", 500

# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    logger.info("Received shutdown signal, shutting down gracefully...")
    exit(0)
