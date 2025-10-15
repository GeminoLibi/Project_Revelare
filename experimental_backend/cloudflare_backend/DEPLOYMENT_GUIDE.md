# Backend Deployment Guide

## Current Issues
The remote D1 database has existing tables with different structures than our new schema, causing conflicts.

## Solution: Migration Script

### Step 1: Deploy Migration
```bash
cd experimental_backend/cloudflare_backend
wrangler d1 execute project-revelare-db --file=./migrate_database.sql --remote
```

### Step 2: Verify Migration
```bash
wrangler d1 execute project-revelare-db --command="SELECT name FROM sqlite_master WHERE type='table';" --remote
```

### Step 3: Check Game Data
```bash
wrangler d1 execute project-revelare-db --command="SELECT game_type, length(game_config) as config_length FROM game_data;" --remote
```

## What the Migration Does
1. Adds missing `game_config` column to existing `game_data` table
2. Adds missing `session_data` column to existing `game_sessions` table  
3. Creates new tables: `schema_version`, `external_services`, `news_articles`
4. Inserts default game configurations for all three games
5. Updates schema version tracking

## Expected Result
After migration, all three GUMSHOE games should be able to:
- Load game data from the backend
- Save/load game states
- Access NPCs and world data
- Function without "Failed to fetch" errors

## Troubleshooting
If migration fails:
1. Check existing table structures first
2. Modify migration script to handle specific conflicts
3. Consider dropping and recreating tables if data loss is acceptable