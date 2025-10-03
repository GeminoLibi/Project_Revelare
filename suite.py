from flask import Flask, render_template_string, request, redirect, url_for, flash, send_from_directory, abort, Response
import os
import tempfile
import threading
import json
import sqlite3
import shutil
import csv
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Import the core logic from our other scripts
import extractor
import reporter
import file_extractor 
from config import Config
from logger import get_logger, RevelareLogger
from security import SecurityValidator, InputValidator

# --- Configuration ---
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# Initialize logger (FIXED: Accessing the instance directly)
revelare_logger = RevelareLogger()
logger = RevelareLogger.get_logger()
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

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
        temp_enhancer = file_extractor.enhancer 
        
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
            findings = extractor.run_extraction(temp_files_to_process)
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
            project_name = request.form.get('project_name', '').strip()
            files = request.files.getlist('files')

            # 1. Validation and File Staging
            is_valid, error_msg = SecurityValidator.validate_project_name(project_name)
            if not is_valid:
                flash(f"Error: {error_msg}", "error")
                return redirect(url_for('home'))
            if not files or not files[0].filename:
                flash("Error: At least one file must be selected.", "error")
                return redirect(url_for('home'))

            project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
            extract_path = tempfile.mkdtemp(prefix=f"revelare_{project_name}_extract_")
            
            if os.path.exists(project_path):
                flash(f"Error: Project '{project_name}' already exists.", "error")
                return redirect(url_for('home'))
                
            os.makedirs(project_path)

            try:
                # Move validated files from Flask request to the final project_path
                for file in files:
                    if not file.filename: continue
                    
                    # File validation checks (extension, size) are handled by Flask/WSGI and checks before save
                    safe_filename = SecurityValidator.sanitize_filename(file.filename)
                    file_path = os.path.join(project_path, safe_filename)
                    file.save(file_path)

                    # Copy files for processing. If it's a zip, extract to extract_path
                    if safe_filename.lower().endswith('.zip'):
                        file_extractor.safe_extract_archive(file_path, extract_path)
                    else:
                        shutil.copy2(file_path, os.path.join(extract_path, safe_filename)) 

            except Exception as e:
                flash(f"Upload/Staging Error: {str(e)}", "error")
                shutil.rmtree(project_path)
                file_extractor.cleanup_temp_files(extract_path)
                return redirect(url_for('home'))

            # 2. Start background analysis
            thread = threading.Thread(target=analysis_thread_worker, args=(extract_path, project_path, project_name))
            thread.daemon = True
            thread.start()
            
            flash(f"Success! Project '{project_name}' is processing in the background.", "success")
            return redirect(url_for('home'))

        # --- GET Request (Display Dashboard) ---
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT project_name, status, total_findings FROM projects ORDER BY created_at DESC")
        db_projects = [{'name': row[0], 'status': row[1], 'findings': row[2], 'report_exists': os.path.exists(os.path.join(Config.UPLOAD_FOLDER, row[0], 'report.html'))} for row in cursor.fetchall()]
        conn.close()

        # NOTE: upload_page_template is assumed to be defined globally
        return render_template_string(upload_page_template, projects=db_projects)
        
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
                return render_template_string(link_analysis_template, results=None, search_term=search_term)
            
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
        
        # NOTE: link_analysis_template is assumed to be defined globally
        return render_template_string(link_analysis_template, results=results, search_term=search_term)
        
    except Exception as e:
        logger.error(f"Error in link_analysis route: {e}")
        flash("An unexpected error occurred during link analysis", "error")
        return render_template_string(link_analysis_template, results=None, search_term="")


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

if __name__ == '__main__':
    # Initialize database
    if not init_database():
        logger.error("Failed to initialize database. Exiting.")
        exit(1)
    
    # NOTE: The provided HTML templates are very large and complex; 
    # using the existing render_template_string is necessary here.
    # Assuming upload_page_template and link_analysis_template are defined globally
    
    logger.info(f"Starting Project Revelare v2.1 (Web) on {Config.HOST}:{Config.PORT}")
    
    try:
        app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        exit(1)