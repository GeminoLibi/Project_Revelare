/**
 * Authentication Routes
 * JWT-based authentication for Cloudflare Workers
 */

import { Hono } from 'hono';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';

import type { Context } from 'hono';

const authRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Validation schemas
const registerSchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email(),
  password: z.string().min(8),
  agency: z.string().optional(),
  phone: z.string().optional(),
  turnstileToken: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  turnstileToken: z.string().optional(),
});

// Helper functions
async function hashPassword(password: string): Promise<string> {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

async function createJWT(payload: any, secret: string, expiresIn: string = '7d'): Promise<string> {
  const secretKey = new TextEncoder().encode(secret);

  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(expiresIn)
    .setIssuedAt()
    .sign(secretKey);
}

async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    const secretKey = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, secretKey);
    return payload;
  } catch {
    return null;
  }
}

async function generateSessionId(): Promise<string> {
  return crypto.randomUUID();
}

// User registration
authRoutes.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const { firstName, lastName, email, password, agency, phone, turnstileToken } = registerSchema.parse(body);

    // Verify Turnstile token if provided (optional for development)
    if (turnstileToken && c.env.CF_TURNSTILE_SECRET) {
      const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: c.env.CF_TURNSTILE_SECRET,
          response: turnstileToken,
          remoteip: c.req.header('CF-Connecting-IP') || 'unknown'
        })
      });

      const turnstileResult = await turnstileResponse.json();
      if (!turnstileResult.success) {
        return c.json({
          error: {
            type: 'validation_error',
            message: 'Security verification failed',
            status_code: 400
          }
        }, 400);
      }
    }

    // Check if user already exists
    const existingUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email.toLowerCase()).first();

    if (existingUser) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'An account with this email already exists',
          status_code: 409
        }
      }, 409);
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Generate verification token
    const verificationToken = crypto.randomUUID();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const { success } = await c.env.DB.prepare(
      `INSERT INTO users (
        email, password_hash, firstName, lastName, agency, phone,
        access_tier, admin_level, account_status, email_verified,
        email_verification_token, email_verification_expires, mfa_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      email.toLowerCase(),
      passwordHash,
      firstName,
      lastName,
      agency || null,
      phone || null,
      'hobbyist',
      'none',
      'pending_verification',
      0,
      verificationToken,
      verificationExpires.toISOString(),
      1 // MFA enabled by default
    ).run();

    if (!success) {
      throw new Error('Failed to create user');
    }

    // Get the created user ID
    const newUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email.toLowerCase()).first();

    // Log user registration
    if (newUser) {
      await c.env.DB.prepare(
        `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, success)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        newUser.id,
        'register',
        'user',
        newUser.id.toString(),
        c.req.header('CF-Connecting-IP') || 'unknown',
        c.req.header('User-Agent') || 'unknown',
        1
      ).run();
    }

    // TODO: Send verification email (implement email service)

    return c.json({
      success: true,
      message: 'Registration successful! Please check your email to verify your account.',
      verificationToken: verificationToken // Remove in production
    });

  } catch (error) {
    console.error('Registration error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Registration failed',
        status_code: 500
      }
    }, 500);
  }
});

// User login
authRoutes.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, turnstileToken } = loginSchema.parse(body);

    // Verify Turnstile token if provided
    if (turnstileToken && c.env.CF_TURNSTILE_SECRET) {
      const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: c.env.CF_TURNSTILE_SECRET,
          response: turnstileToken,
          remoteip: c.req.header('CF-Connecting-IP') || 'unknown'
        })
      });

      const turnstileResult = await turnstileResponse.json();
      if (!turnstileResult.success) {
        return c.json({
          error: {
            type: 'validation_error',
            message: 'Security verification failed',
            status_code: 400
          }
        }, 400);
      }
    }

    // Get user
    const user = await c.env.DB.prepare(
      `SELECT id, email, password_hash, access_tier, admin_level,
              account_status, email_verified, failed_login_attempts,
              account_locked_until, last_login_at
       FROM users WHERE email = ?`
    ).bind(email.toLowerCase()).first();

    if (!user) {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Invalid credentials',
          status_code: 401
        }
      }, 401);
    }

    // Check if account is locked
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Account is temporarily locked due to too many failed login attempts',
          status_code: 423
        }
      }, 423);
    }

    // Check if email is verified
    if (!user.email_verified) {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Please verify your email address before logging in',
          requiresVerification: true,
          status_code: 403
        }
      }, 403);
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password_hash);

    if (!isValidPassword) {
      // Increment failed attempts
      const newFailedAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;

      if (newFailedAttempts >= 5) {
        lockUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutes
      }

      await c.env.DB.prepare(
        "UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?"
      ).bind(newFailedAttempts, lockUntil, user.id).run();

      // Log failed login attempt
      await c.env.DB.prepare(
        `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, success, error_message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        user.id,
        'login_attempt',
        'user',
        user.id.toString(),
        c.req.header('CF-Connecting-IP') || 'unknown',
        c.req.header('User-Agent') || 'unknown',
        0,
        'Invalid password'
      ).run();

      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Invalid credentials',
          status_code: 401
        }
      }, 401);
    }

    // Reset failed login attempts
    await c.env.DB.prepare(
      "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login_at = ? WHERE id = ?"
    ).bind(new Date().toISOString(), user.id).run();

    // Log successful login
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      user.id,
      'login',
      'user',
      user.id.toString(),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    // Create session
    const sessionId = await generateSessionId();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await c.env.DB.prepare(
      `INSERT INTO user_sessions (
        user_id, session_id, ip_address, user_agent, expires_at
      ) VALUES (?, ?, ?, ?, ?)`
    ).bind(
      user.id,
      sessionId,
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      expiresAt.toISOString()
    ).run();

    // Create JWT tokens
    const accessToken = await createJWT(
      {
        sub: user.email,
        user_id: user.id,
        tier: user.access_tier,
        admin_level: user.admin_level,
        type: 'access'
      },
      c.env.JWT_SECRET,
      '30m'
    );

    const refreshToken = await createJWT(
      {
        sub: user.email,
        user_id: user.id,
        type: 'refresh'
      },
      c.env.JWT_SECRET,
      '7d'
    );

    // Store tokens in KV for validation
    await c.env.REVELARE_KV.put(
      `auth_${accessToken}`,
      JSON.stringify({ userId: user.id, tier: user.access_tier }),
      { expirationTtl: 30 * 60 } // 30 minutes
    );

    await c.env.REVELARE_KV.put(
      `refresh_${refreshToken}`,
      JSON.stringify({ userId: user.id }),
      { expirationTtl: 7 * 24 * 60 * 60 } // 7 days
    );

    return c.json({
      success: true,
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'bearer',
      expires_in: 30 * 60,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        access_tier: user.access_tier,
        is_admin: user.admin_level !== 'none',
        email_verified: user.email_verified === 1
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Login failed',
        status_code: 500
      }
    }, 500);
  }
});

// Refresh access token
authRoutes.post('/refresh', async (c) => {
  try {
    const body = await c.req.json();
    const { refreshToken } = z.object({ refreshToken: z.string() }).parse(body);

    // Verify refresh token
    const payload = await verifyJWT(refreshToken, c.env.JWT_SECRET);

    if (!payload || payload.type !== 'refresh') {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Invalid refresh token',
          status_code: 401
        }
      }, 401);
    }

    // Check if refresh token exists in KV
    const storedToken = await c.env.REVELARE_KV.get(`refresh_${refreshToken}`);
    if (!storedToken) {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'Refresh token not found or expired',
          status_code: 401
        }
      }, 401);
    }

    // Get user
    const user = await c.env.DB.prepare(
      "SELECT id, email, access_tier, admin_level, account_status FROM users WHERE id = ? AND account_status = 'active'"
    ).bind(payload.user_id).first();

    if (!user) {
      return c.json({
        error: {
          type: 'authentication_error',
          message: 'User not found or inactive',
          status_code: 401
        }
      }, 401);
    }

    // Generate new access token
    const newAccessToken = await createJWT(
      {
        sub: user.email,
        user_id: user.id,
        tier: user.access_tier,
        admin_level: user.admin_level,
        type: 'access'
      },
      c.env.JWT_SECRET,
      '30m'
    );

    // Update KV with new access token
    await c.env.REVELARE_KV.put(
      `auth_${newAccessToken}`,
      JSON.stringify({ userId: user.id, tier: user.access_tier }),
      { expirationTtl: 30 * 60 }
    );

    return c.json({
      success: true,
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: 30 * 60
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Token refresh failed',
        status_code: 500
      }
    }, 500);
  }
});

// Logout (revoke tokens)
authRoutes.post('/logout', async (c) => {
  try {
    const payload = c.get('jwtPayload');

    // Revoke all user sessions
    await c.env.DB.prepare(
      "UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1"
    ).bind(payload.user_id).run();

    // Log logout
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      payload.user_id,
      'logout',
      'user',
      payload.user_id.toString(),
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      1
    ).run();

    // Note: In a real implementation, you'd also invalidate JWT tokens
    // For now, we rely on session revocation

    return c.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Logout failed',
        status_code: 500
      }
    }, 500);
  }
});

// Note: /me endpoint moved to main index.ts for better organization

// Verify email
authRoutes.post('/verify-email', async (c) => {
  try {
    const body = await c.req.json();
    const { token } = z.object({ token: z.string() }).parse(body);

    const user = await c.env.DB.prepare(
      `SELECT id, email, first_name FROM users
       WHERE email_verification_token = ? AND email_verification_expires > ?
       AND email_verified = 0`
    ).bind(token, new Date().toISOString()).first();

    if (!user) {
      return c.json({
        error: {
          type: 'validation_error',
          message: 'Invalid or expired verification token',
          status_code: 400
        }
      }, 400);
    }

    // Update user as verified
    await c.env.DB.prepare(
      `UPDATE users SET email_verified = 1, account_status = 'active',
       email_verification_token = NULL, email_verification_expires = NULL
       WHERE id = ?`
    ).bind(user.id).run();

    return c.json({
      success: true,
      message: 'Email verified successfully'
    });

  } catch (error) {
    console.error('Email verification error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Email verification failed',
        status_code: 500
      }
    }, 500);
  }
});

export { authRoutes };
