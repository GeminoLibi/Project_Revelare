-- Migration script to update existing database schema
-- This handles the conflicts between existing tables and new schema

-- Add missing columns to existing game_data table
ALTER TABLE game_data ADD COLUMN game_config TEXT;

-- Add missing columns to existing game_sessions table  
ALTER TABLE game_sessions ADD COLUMN session_data TEXT;

-- Create new tables that don't exist yet
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS external_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    service_type TEXT NOT NULL,
    config_data TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS news_articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    source TEXT,
    url TEXT,
    published_at DATETIME,
    category TEXT,
    tags TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default game configurations
INSERT OR REPLACE INTO game_data (game_type, game_config) VALUES 
('noir', '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}'),
('fantasy', '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}'),
('cyberpunk', '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}');

-- Update schema version
INSERT OR REPLACE INTO schema_version (version) VALUES (1);
