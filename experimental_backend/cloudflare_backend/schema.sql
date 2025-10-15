-- Project Revelare D1 Database Schema
-- Compatible with Cloudflare D1 (SQLite-based)
-- Generated: 2024-10-13

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

-- Insert current version
INSERT OR IGNORE INTO schema_version (version, description) VALUES (3, 'Added game_saves, game_data, and game_sessions tables');

-- Game saves table for GUMSHOE games
CREATE TABLE IF NOT EXISTS game_saves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    game_type TEXT NOT NULL, -- 'noir', 'fantasy', 'cyberpunk'
    save_name TEXT NOT NULL,
    game_data TEXT NOT NULL, -- JSON string of game state
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, game_type, save_name)
);

-- Game data table for game configurations and static data
CREATE TABLE IF NOT EXISTS game_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_type TEXT UNIQUE NOT NULL, -- 'noir', 'fantasy', 'cyberpunk'
    game_config TEXT NOT NULL, -- JSON string of game configuration
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Game sessions table for tracking active game sessions
CREATE TABLE IF NOT EXISTS game_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    game_type TEXT NOT NULL, -- 'noir', 'fantasy', 'cyberpunk'
    session_data TEXT, -- JSON string of current session state
    is_active INTEGER NOT NULL DEFAULT 1,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API Keys and External Services table
CREATE TABLE IF NOT EXISTS external_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT UNIQUE NOT NULL,
    service_type TEXT NOT NULL, -- 'virus_scan', 'email', 'ai', 'geolocation', etc.
    api_key_encrypted TEXT, -- Encrypted API key
    api_key_hash TEXT, -- Hash of the API key for verification
    endpoint_url TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    rate_limit_per_minute INTEGER DEFAULT 1000,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    agency TEXT,
    phone TEXT,
    access_tier TEXT NOT NULL DEFAULT 'hobbyist',
    admin_level TEXT NOT NULL DEFAULT 'none',
    account_status TEXT NOT NULL DEFAULT 'pending_verification',
    email_verified INTEGER NOT NULL DEFAULT 0,
    email_verification_token TEXT,
    email_verification_expires TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    account_locked_until TEXT,
    last_login_at TEXT,
    password_changed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    priority TEXT NOT NULL DEFAULT 'normal',
    classification_level TEXT NOT NULL DEFAULT 'unclassified',
    incident_date TEXT,
    start_date TEXT,
    end_date TEXT,
    processing_status TEXT NOT NULL DEFAULT 'pending',
    processing_progress INTEGER NOT NULL DEFAULT 0,
    processing_message TEXT,
    tags TEXT, -- JSON string
    custom_fields TEXT, -- JSON string
    total_files INTEGER NOT NULL DEFAULT 0,
    total_size INTEGER NOT NULL DEFAULT 0,
    processed_files INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    assigned_to INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

-- Evidence files table
CREATE TABLE IF NOT EXISTS evidence_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_hash TEXT NOT NULL,
    mime_type TEXT,
    file_type TEXT,
    file_category TEXT,
    status TEXT NOT NULL DEFAULT 'uploaded',
    processing_message TEXT,
    processed_at TEXT,
    virus_scan_result TEXT,
    virus_scan_details TEXT, -- JSON string
    is_malicious INTEGER NOT NULL DEFAULT 0,
    file_metadata TEXT, -- JSON string
    extracted_text TEXT,
    storage_provider TEXT NOT NULL DEFAULT 'r2',
    storage_bucket TEXT,
    storage_key TEXT,
    uploaded_by INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    evidence_file_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    confidence INTEGER NOT NULL DEFAULT 100,
    severity TEXT,
    tags TEXT, -- JSON string
    enriched_data TEXT, -- JSON string
    external_refs TEXT, -- JSON string
    processor TEXT,
    processing_metadata TEXT, -- JSON string
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_file_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

-- Case notes table
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_internal INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Processing jobs table
CREATE TABLE IF NOT EXISTS processing_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    job_type TEXT NOT NULL,
    job_status TEXT NOT NULL DEFAULT 'pending',
    progress INTEGER NOT NULL DEFAULT 0,
    current_step TEXT,
    message TEXT,
    started_at TEXT,
    completed_at TEXT,
    estimated_completion TEXT,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    job_config TEXT, -- JSON string
    priority INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

-- News articles table for cybersecurity news aggregation
CREATE TABLE IF NOT EXISTS news_articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    link TEXT UNIQUE NOT NULL,
    description TEXT,
    pub_date TEXT,
    source TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'threat',
    crawled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table for security and compliance
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL, -- 'login', 'logout', 'create_case', 'update_user', etc.
    resource_type TEXT, -- 'user', 'case', 'file', 'system'
    resource_id TEXT, -- ID of the affected resource
    old_values TEXT, -- JSON string of old values (for updates)
    new_values TEXT, -- JSON string of new values (for updates)
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(account_status);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(access_tier);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON user_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_cases_created_by ON cases(created_by);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assigned_to ON cases(assigned_to);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence_files(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence_files(status);
CREATE INDEX IF NOT EXISTS idx_evidence_uploaded_by ON evidence_files(uploaded_by);

CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);

CREATE INDEX IF NOT EXISTS idx_case_notes_case_id ON case_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_case_notes_user_id ON case_notes(user_id);

CREATE INDEX IF NOT EXISTS idx_processing_jobs_case_id ON processing_jobs(case_id);
CREATE INDEX IF NOT EXISTS idx_processing_jobs_status ON processing_jobs(job_status);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

CREATE INDEX IF NOT EXISTS idx_external_services_type ON external_services(service_type);
CREATE INDEX IF NOT EXISTS idx_external_services_active ON external_services(is_active);

CREATE INDEX IF NOT EXISTS idx_news_articles_source ON news_articles(source);
CREATE INDEX IF NOT EXISTS idx_news_articles_category ON news_articles(category);
CREATE INDEX IF NOT EXISTS idx_news_articles_pub_date ON news_articles(pub_date);
CREATE INDEX IF NOT EXISTS idx_news_articles_crawled_at ON news_articles(crawled_at);

CREATE INDEX IF NOT EXISTS idx_game_saves_user_id ON game_saves(user_id);
CREATE INDEX IF NOT EXISTS idx_game_saves_game_type ON game_saves(game_type);
CREATE INDEX IF NOT EXISTS idx_game_saves_user_game ON game_saves(user_id, game_type);

CREATE INDEX IF NOT EXISTS idx_game_sessions_user_id ON game_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_game_sessions_game_type ON game_sessions(game_type);
CREATE INDEX IF NOT EXISTS idx_game_sessions_active ON game_sessions(is_active);

-- Insert default admin user (for initial setup)
-- Note: This will only run if no users exist yet
INSERT OR IGNORE INTO users (
    email,
    password_hash,
    first_name,
    last_name,
    access_tier,
    admin_level,
    account_status,
    email_verified,
    mfa_enabled
) VALUES (
    'admin@project-revelare.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeehR62ZfKJvnhl2e', -- "admin123" hashed with bcrypt
    'System',
    'Administrator',
    'admin',
    'super_admin',
    'active',
    1,
    0
);

-- Insert default game configurations
INSERT OR IGNORE INTO game_data (game_type, game_config) VALUES
('noir', '{
  "name": "GUMSHOE Noir",
  "description": "Classic detective noir setting",
  "defaultScenario": "The Missing Heiress",
  "abilities": ["Athletics", "Burglary", "Drive", "Explosives", "Filch", "Gambling", "Hacking", "Impersonate", "Mechanics", "Medicine", "Network", "Piloting", "Preparedness", "Research", "Ride", "Scuffling", "Sense Trouble", "Shadowing", "Shooting", "Shrink", "Stealth", "Streetwise", "Surveillance", "Weapons"],
  "defaultAbilities": ["Athletics", "Drive", "Preparedness", "Research", "Scuffling", "Sense Trouble", "Shadowing", "Shooting", "Stealth", "Streetwise"]
}'),
('fantasy', '{
  "name": "GUMSHOE Fantasy",
  "description": "Medieval fantasy setting",
  "defaultScenario": "The Dragon''s Hoard",
  "abilities": ["Athletics", "Burglary", "Disguise", "Explosives", "Filch", "Gambling", "Hacking", "Impersonate", "Mechanics", "Medicine", "Network", "Piloting", "Preparedness", "Research", "Ride", "Scuffling", "Sense Trouble", "Shadowing", "Shooting", "Shrink", "Sorcery", "Stealth", "Streetwise", "Surveillance", "Weapons"],
  "defaultAbilities": ["Athletics", "Disguise", "Preparedness", "Research", "Scuffling", "Sense Trouble", "Shadowing", "Sorcery", "Stealth", "Weapons"]
}'),
('cyberpunk', '{
  "name": "GUMSHOE Cyberpunk",
  "description": "High-tech dystopian future",
  "defaultScenario": "The Corporate Conspiracy",
  "abilities": ["Athletics", "Burglary", "Digital Intrusion", "Disguise", "Explosives", "Filch", "Gambling", "Hacking", "Impersonate", "Mechanics", "Medicine", "Network", "Piloting", "Preparedness", "Research", "Ride", "Scuffling", "Sense Trouble", "Shadowing", "Shooting", "Shrink", "Stealth", "Streetwise", "Surveillance", "Weapons"],
  "defaultAbilities": ["Athletics", "Digital Intrusion", "Hacking", "Preparedness", "Research", "Scuffling", "Sense Trouble", "Shadowing", "Shooting", "Stealth"]
}');
