/**
 * Game Routes
 * Endpoints for GUMSHOE game save/load functionality
 */

import { Hono } from 'hono';
import { z } from 'zod';

const gameRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Test endpoint
gameRoutes.get('/test', (c) => {
  return c.json({ message: 'Games API is working!' });
});

// Save game state
gameRoutes.post('/save', async (c) => {
  try {
    const body = await c.req.json();

    const saveSchema = z.object({
      gameType: z.enum(['noir', 'fantasy', 'cyberpunk']),
      saveName: z.string().min(1).max(100),
      gameData: z.any() // JSON object
    });

    const { gameType, saveName, gameData } = saveSchema.parse(body);

    // Get user ID from JWT token
    const payload = c.get('jwtPayload');

    // Check if save already exists
    const existingSave = await c.env.DB.prepare(
      "SELECT id FROM game_saves WHERE user_id = ? AND game_type = ? AND save_name = ?"
    ).bind(payload.user_id, gameType, saveName).first();

    if (existingSave) {
      // Update existing save
      await c.env.DB.prepare(
        "UPDATE game_saves SET game_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(JSON.stringify(gameData), existingSave.id).run();
    } else {
      // Create new save
      await c.env.DB.prepare(
        "INSERT INTO game_saves (user_id, game_type, save_name, game_data) VALUES (?, ?, ?, ?)"
      ).bind(payload.user_id, gameType, saveName, JSON.stringify(gameData)).run();
    }

    return c.json({
      success: true,
      message: 'Game saved successfully'
    });

  } catch (error) {
    console.error('Save game error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to save game',
        status_code: 500
      }
    }, 500);
  }
});

// Load specific game save
gameRoutes.get('/load/:gameType/:saveName', async (c) => {
  try {
    const gameType = c.req.param('gameType');
    const saveName = c.req.param('saveName');

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    // Get user ID from JWT token
    const payload = c.get('jwtPayload');

    // Get save data
    const save = await c.env.DB.prepare(
      "SELECT game_data FROM game_saves WHERE user_id = ? AND game_type = ? AND save_name = ?"
    ).bind(payload.user_id, gameType, saveName).first();

    if (!save) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'Game save not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json({
      gameData: JSON.parse(save.game_data)
    });

  } catch (error) {
    console.error('Load game error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to load game',
        status_code: 500
      }
    }, 500);
  }
});

// List saves for a game type
gameRoutes.get('/saves/:gameType', async (c) => {
  try {
    const gameType = c.req.param('gameType');

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    // Get user ID from JWT token
    const payload = c.get('jwtPayload');

    // Get user's saves for this game type
    const saves = await c.env.DB.prepare(
      `SELECT save_name, updated_at FROM game_saves
       WHERE user_id = ? AND game_type = ?
       ORDER BY updated_at DESC`
    ).bind(payload.user_id, gameType).all();

    return c.json({
      saves: saves.results || []
    });

  } catch (error) {
    console.error('List saves error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to list saves',
        status_code: 500
      }
    }, 500);
  }
});

// Delete game save
gameRoutes.delete('/:gameType/:saveName', async (c) => {
  try {
    const gameType = c.req.param('gameType');
    const saveName = c.req.param('saveName');

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    // Get user ID from JWT token
    const payload = c.get('jwtPayload');

    // Delete save
    const result = await c.env.DB.prepare(
      "DELETE FROM game_saves WHERE user_id = ? AND game_type = ? AND save_name = ?"
    ).bind(payload.user_id, gameType, saveName).run();

    if (result.changes === 0) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'Game save not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json({
      success: true,
      message: 'Game save deleted successfully'
    });

  } catch (error) {
    console.error('Delete save error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to delete save',
        status_code: 500
      }
    }, 500);
  }
});

// Get game data/configuration
gameRoutes.get('/data/:gameType', async (c) => {
  try {
    const gameType = c.req.param('gameType');

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    // Get game data
    console.log(`Fetching game data for type: ${gameType}`);
    const gameData = await c.env.DB.prepare(
      "SELECT game_config FROM game_data WHERE game_type = ?"
    ).bind(gameType).first();

    console.log('Game data query result:', gameData);

    if (!gameData) {
      console.log('No game data found for type:', gameType);
      return c.json({
        error: {
          type: 'not_found',
          message: 'Game data not found',
          status_code: 404
        }
      }, 404);
    }

    if (!gameData.game_config) {
      console.log('Game config is null for type:', gameType);
      return c.json({
        error: {
          type: 'not_found',
          message: 'Game configuration not found',
          status_code: 404
        }
      }, 404);
    }

    try {
      const gameConfig = JSON.parse(gameData.game_config);
      console.log('Successfully parsed game config for type:', gameType);
      return c.json({
        gameConfig: gameConfig
      });
    } catch (parseError) {
      console.error('JSON parse error for game type:', gameType, parseError);
      return c.json({
        error: {
          type: 'internal_server_error',
          message: 'Invalid game configuration data',
          status_code: 500
        }
      }, 500);
    }

  } catch (error) {
    console.error('Get game data error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: `Failed to get game data: ${error.message}`,
        status_code: 500,
        details: error.toString()
      }
    }, 500);
  }
});

// Initialize game data (admin endpoint)
gameRoutes.post('/data/:gameType', async (c) => {
  try {
    const gameType = c.req.param('gameType');
    const body = await c.req.json();

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    const configSchema = z.object({
      gameConfig: z.any() // JSON object with game configuration
    });

    const { gameConfig } = configSchema.parse(body);

    // Check if game data already exists
    const existingData = await c.env.DB.prepare(
      "SELECT id FROM game_data WHERE game_type = ?"
    ).bind(gameType).first();

    if (existingData) {
      // Update existing game data
      await c.env.DB.prepare(
        "UPDATE game_data SET game_config = ?, updated_at = CURRENT_TIMESTAMP WHERE game_type = ?"
      ).bind(JSON.stringify(gameConfig), gameType).run();
    } else {
      // Create new game data
      await c.env.DB.prepare(
        "INSERT INTO game_data (game_type, game_config) VALUES (?, ?)"
      ).bind(gameType, JSON.stringify(gameConfig)).run();
    }

    return c.json({
      success: true,
      message: 'Game data updated successfully'
    });

  } catch (error) {
    console.error('Update game data error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to update game data',
        status_code: 500
      }
    }, 500);
  }
});

// Start new game session
gameRoutes.post('/session/:gameType', async (c) => {
  try {
    const gameType = c.req.param('gameType');

    // Validate game type
    if (!['noir', 'fantasy', 'cyberpunk'].includes(gameType)) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid game type',
          status_code: 400
        }
      }, 400);
    }

    // Get user ID from JWT token
    const payload = c.get('jwtPayload');

    // Create new game session
    await c.env.DB.prepare(
      "INSERT INTO game_sessions (user_id, game_type, session_data) VALUES (?, ?, ?)"
    ).bind(payload.user_id, gameType, JSON.stringify({})).run();

    return c.json({
      success: true,
      message: 'Game session started'
    });

  } catch (error) {
    console.error('Start game session error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to start game session',
        status_code: 500
      }
    }, 500);
  }
});

export { gameRoutes };
