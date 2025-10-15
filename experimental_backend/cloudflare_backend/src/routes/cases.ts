/**
 * Case Management Routes
 * Endpoints for case administration
 */

import { Hono } from 'hono';
import { z } from 'zod';

const caseRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Get all cases (admin only)
caseRoutes.get('/', async (c) => {
  try {
    const cases = await c.env.DB.prepare(
      `SELECT c.id, c.case_number, c.title, c.description, c.status, c.priority,
              c.classification_level, c.created_by, c.assigned_to, c.created_at,
              u.first_name, u.last_name, u.email as creator_email
       FROM cases c
       LEFT JOIN users u ON c.created_by = u.id
       ORDER BY c.created_at DESC`
    ).all();

    return c.json({
      cases: cases.results || [],
      total: cases.results?.length || 0
    });

  } catch (error) {
    console.error('Get cases error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get cases',
        status_code: 500
      }
    }, 500);
  }
});

// Get case by ID (admin only)
caseRoutes.get('/:caseId', async (c) => {
  try {
    const caseId = c.req.param('caseId');

    const caseData = await c.env.DB.prepare(
      `SELECT c.id, c.case_number, c.title, c.description, c.status, c.priority,
              c.classification_level, c.created_by, c.assigned_to, c.created_at,
              c.total_files, c.total_size, c.processed_files,
              u.first_name, u.last_name, u.email as creator_email
       FROM cases c
       LEFT JOIN users u ON c.created_by = u.id
       WHERE c.id = ?`
    ).bind(caseId).first();

    if (!caseData) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'Case not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json(caseData);

  } catch (error) {
    console.error('Get case error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get case',
        status_code: 500
      }
    }, 500);
  }
});

// Create new case (admin only)
caseRoutes.post('/', async (c) => {
  try {
    const body = await c.req.json();

    const createSchema = z.object({
      case_number: z.string().min(1),
      title: z.string().min(1),
      description: z.string().optional(),
      priority: z.enum(['low', 'normal', 'high', 'critical']).default('normal'),
      classification_level: z.enum(['unclassified', 'confidential', 'secret', 'top_secret']).default('unclassified'),
      assigned_to: z.number().optional()
    });

    const caseData = createSchema.parse(body);

    // Check if case number already exists
    const existingCase = await c.env.DB.prepare(
      "SELECT id FROM cases WHERE case_number = ?"
    ).bind(caseData.case_number).first();

    if (existingCase) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Case number already exists',
          status_code: 409
        }
      }, 409);
    }

    // Create case
    const { success } = await c.env.DB.prepare(
      `INSERT INTO cases (
        case_number, title, description, priority, classification_level, assigned_to, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      caseData.case_number,
      caseData.title,
      caseData.description || null,
      caseData.priority,
      caseData.classification_level,
      caseData.assigned_to || null,
      c.get('jwtPayload').user_id // Current admin user
    ).run();

    if (!success) {
      throw new Error('Failed to create case');
    }

    // Log case creation
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      c.get('jwtPayload').user_id, // Admin user who created the case
      'create_case',
      'case',
      caseData.case_number, // Use case number as resource ID
      JSON.stringify(caseData),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    return c.json({
      success: true,
      message: 'Case created successfully'
    });

  } catch (error) {
    console.error('Create case error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to create case',
        status_code: 500
      }
    }, 500);
  }
});

// Update case (admin only)
caseRoutes.put('/:caseId', async (c) => {
  try {
    const caseId = c.req.param('caseId');
    const body = await c.req.json();

    const updateSchema = z.object({
      title: z.string().optional(),
      description: z.string().optional(),
      status: z.enum(['draft', 'active', 'processing', 'completed', 'archived', 'cancelled']).optional(),
      priority: z.enum(['low', 'normal', 'high', 'critical']).optional(),
      classification_level: z.enum(['unclassified', 'confidential', 'secret', 'top_secret']).optional(),
      assigned_to: z.number().optional()
    });

    const updates = updateSchema.parse(body);

    // Build dynamic update query
    const updateFields = [];
    const bindValues = [];

    Object.entries(updates).forEach(([key, value]) => {
      if (value !== undefined) {
        updateFields.push(`${key} = ?`);
        bindValues.push(value);
      }
    });

    if (updateFields.length === 0) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'No valid fields to update',
          status_code: 400
        }
      }, 400);
    }

    bindValues.push(caseId);

    const query = `UPDATE cases SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    await c.env.DB.prepare(query).bind(...bindValues).run();

    // Log case update
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      c.get('jwtPayload').user_id, // Admin user who made the change
      'update_case',
      'case',
      caseId,
      JSON.stringify(updates),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    return c.json({
      success: true,
      message: 'Case updated successfully'
    });

  } catch (error) {
    console.error('Update case error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to update case',
        status_code: 500
      }
    }, 500);
  }
});

// Delete case (admin only)
caseRoutes.delete('/:caseId', async (c) => {
  try {
    const caseId = c.req.param('caseId');

    // Check if case exists
    const caseData = await c.env.DB.prepare(
      "SELECT id FROM cases WHERE id = ?"
    ).bind(caseId).first();

    if (!caseData) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'Case not found',
          status_code: 404
        }
      }, 404);
    }

    // Log case deletion before deleting
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      c.get('jwtPayload').user_id, // Admin user who deleted the case
      'delete_case',
      'case',
      caseId,
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    // Delete case (cascade will handle related records)
    await c.env.DB.prepare("DELETE FROM cases WHERE id = ?").bind(caseId).run();

    return c.json({
      success: true,
      message: 'Case deleted successfully'
    });

  } catch (error) {
    console.error('Delete case error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to delete case',
        status_code: 500
      }
    }, 500);
  }
});

export { caseRoutes };
