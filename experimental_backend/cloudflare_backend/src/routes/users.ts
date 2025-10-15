/**
 * User Management Routes (Admin)
 * Endpoints for user administration
 */

import { Hono } from 'hono';
import { z } from 'zod';

const userRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Get all users (admin only)
userRoutes.get('/', async (c) => {
  try {
    const users = await c.env.DB.prepare(
      `SELECT id, email, first_name, last_name, agency, access_tier, admin_level,
              account_status, email_verified, last_login_at, created_at
       FROM users ORDER BY created_at DESC`
    ).all();

    return c.json({
      users: users.results || [],
      total: users.results?.length || 0
    });

  } catch (error) {
    console.error('Get users error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get users',
        status_code: 500
      }
    }, 500);
  }
});

// Get user by ID (admin only)
userRoutes.get('/:userId', async (c) => {
  try {
    const userId = c.req.param('userId');

    const user = await c.env.DB.prepare(
      `SELECT id, email, first_name, last_name, agency, phone, access_tier, admin_level,
              account_status, email_verified, last_login_at, created_at
       FROM users WHERE id = ?`
    ).bind(userId).first();

    if (!user) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'User not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json(user);

  } catch (error) {
    console.error('Get user error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get user',
        status_code: 500
      }
    }, 500);
  }
});

// Update user (admin only)
userRoutes.put('/:userId', async (c) => {
  try {
    const userId = c.req.param('userId');
    const body = await c.req.json();

    const updateSchema = z.object({
      first_name: z.string().optional(),
      last_name: z.string().optional(),
      agency: z.string().optional(),
      phone: z.string().optional(),
      access_tier: z.string().optional(),
      admin_level: z.string().optional(),
      account_status: z.string().optional()
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

    bindValues.push(userId);

    const query = `UPDATE users SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    await c.env.DB.prepare(query).bind(...bindValues).run();

    // Get updated user
    const updatedUser = await c.env.DB.prepare(
      `SELECT id, email, first_name, last_name, agency, phone, access_tier, admin_level,
              account_status, email_verified, last_login_at, created_at
       FROM users WHERE id = ?`
    ).bind(userId).first();

    // Log user update
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, old_values, new_values, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      c.get('jwtPayload').user_id, // Admin user who made the change
      'update_user',
      'user',
      userId,
      JSON.stringify({}), // Would need to store old values
      JSON.stringify(updates),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    return c.json(updatedUser);

  } catch (error) {
    console.error('Update user error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to update user',
        status_code: 500
      }
    }, 500);
  }
});

// Update user status (admin only)
userRoutes.patch('/:userId/status', async (c) => {
  try {
    const userId = c.req.param('userId');
    const body = await c.req.json();

    const statusSchema = z.object({
      account_status: z.enum(['active', 'suspended', 'deactivated'])
    });

    const { account_status } = statusSchema.parse(body);

    await c.env.DB.prepare(
      "UPDATE users SET account_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).bind(account_status, userId).run();

    // Log status change
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      c.get('jwtPayload').user_id, // Admin user who made the change
      'update_user_status',
      'user',
      userId,
      JSON.stringify({ account_status }),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    return c.json({
      success: true,
      message: 'User status updated successfully'
    });

  } catch (error) {
    console.error('Update user status error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to update user status',
        status_code: 500
      }
    }, 500);
  }
});

// Create new user (admin only)
userRoutes.post('/create', async (c) => {
  try {
    const body = await c.req.json();

    const createSchema = z.object({
      first_name: z.string().min(1),
      last_name: z.string().min(1),
      email: z.string().email(),
      password: z.string().min(8),
      agency: z.string().optional(),
      phone: z.string().optional(),
      access_tier: z.enum(['hobbyist', 'professional', 'enterprise', 'admin']).default('hobbyist'),
      admin_level: z.enum(['none', 'moderator', 'admin', 'super_admin']).default('none')
    });

    const userData = createSchema.parse(body);

    // Check if user already exists
    const existingUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(userData.email.toLowerCase()).first();

    if (existingUser) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'User with this email already exists',
          status_code: 409
        }
      }, 409);
    }

    // Hash password
    const bcrypt = await import('bcryptjs');
    const passwordHash = await bcrypt.hash(userData.password, 12);

    // Generate verification token
    const verificationToken = crypto.randomUUID();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    // Create user
    const { success } = await c.env.DB.prepare(
      `INSERT INTO users (
        email, password_hash, first_name, last_name, agency, phone,
        access_tier, admin_level, account_status, email_verified,
        email_verification_token, email_verification_expires, mfa_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      userData.email.toLowerCase(),
      passwordHash,
      userData.first_name,
      userData.last_name,
      userData.agency || null,
      userData.phone || null,
      userData.access_tier,
      userData.admin_level,
      'active', // Admin-created users are active
      1, // Email verified for admin-created users
      verificationToken,
      verificationExpires,
      1 // MFA enabled by default
    ).run();

    if (!success) {
      throw new Error('Failed to create user');
    }

    // Get the created user ID for logging
    const createdUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(userData.email.toLowerCase()).first();

    // Log user creation
    if (createdUser) {
      await c.env.DB.prepare(
        `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, user_agent, success)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        c.get('jwtPayload').user_id, // Admin user who created
        'create_user',
        'user',
        createdUser.id.toString(),
        JSON.stringify(userData),
        c.req.header('CF-Connecting-IP') || 'unknown',
        c.req.header('User-Agent') || 'unknown',
        1
      ).run();
    }

    return c.json({
      success: true,
      message: 'User created successfully'
    });

  } catch (error) {
    console.error('Create user error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to create user',
        status_code: 500
      }
    }, 500);
  }
});

// Get audit logs (admin only)
userRoutes.get('/audit-logs', async (c) => {
  try {
    const logs = await c.env.DB.prepare(
      `SELECT al.id, al.user_id, al.action, al.resource_type, al.resource_id,
              al.ip_address, al.user_agent, al.success, al.error_message, al.created_at,
              u.first_name, u.last_name, u.email as user_email
       FROM audit_logs al
       LEFT JOIN users u ON al.user_id = u.id
       ORDER BY al.created_at DESC
       LIMIT 100`
    ).all();

    return c.json({
      logs: logs.results || [],
      total: logs.results?.length || 0
    });

  } catch (error) {
    console.error('Get audit logs error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get audit logs',
        status_code: 500
      }
    }, 500);
  }
});

export { userRoutes };
