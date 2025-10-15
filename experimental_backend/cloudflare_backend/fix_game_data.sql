-- Fix game data with proper JSON formatting
UPDATE game_data SET game_config = '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}' WHERE game_type = 'noir';
UPDATE game_data SET game_config = '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}' WHERE game_type = 'fantasy';
UPDATE game_data SET game_config = '{"worldMap": {}, "npcStats": {}, "items": {}, "features": {}, "npcs": {}}' WHERE game_type = 'cyberpunk';
