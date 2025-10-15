-- Migration script to update existing tables for game functionality
-- This adds missing columns without recreating existing tables

-- Add game_config column to game_data table if it doesn't exist
ALTER TABLE game_data ADD COLUMN game_config TEXT;

-- Add missing columns to game_sessions table if they don't exist
ALTER TABLE game_sessions ADD COLUMN session_data TEXT;
ALTER TABLE game_sessions ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE game_sessions ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- Insert default game configurations if they don't exist
INSERT OR IGNORE INTO game_data (game_type, game_config) VALUES 
('noir', '{"worldMap": {}, "items": {}, "npcs": {}, "features": {}}'),
('fantasy', '{"worldMap": {}, "items": {}, "npcs": {}, "features": {}}'),
('cyberpunk', '{"worldMap": {}, "items": {}, "npcs": {}, "features": {}}');

-- Update existing game_data records to have empty game_config if they don't have one
UPDATE game_data SET game_config = '{"worldMap": {}, "items": {}, "npcs": {}, "features": {}}' 
WHERE game_config IS NULL;
