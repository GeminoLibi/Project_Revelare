/**
 * Project Revelare Backend - Cloudflare Workers
 * Main worker file implementing the API for digital forensics platform
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
// import { rateLimiter } from 'hono/rate-limiter';
import { jwt } from 'hono/jwt';

import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';
import { caseRoutes } from './routes/cases';
import { fileRoutes } from './routes/files';
import { newsRoutes } from './routes/news';
import { gameRoutes } from './routes/games';
// import { evidenceRoutes } from './routes/evidence';
// import { analysisRoutes } from './routes/analysis';

// Import types
import type { Context, Next } from 'hono';

// Create Hono app
const app = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    R2_EVIDENCE_BUCKET: R2Bucket;
    JWT_SECRET: string;
  };
}>();

// Global middleware
app.use('*', logger());
app.use('*', prettyJSON());

// CORS configuration
app.use('*', cors({
  origin: (origin, c) => {
    // Get allowed origins from environment variable with fallback
    const allowedOrigins = (c.env && c.env.ALLOWED_ORIGINS) 
      ? c.env.ALLOWED_ORIGINS.split(',')
      : [
          'https://project-revelare.com',
          'https://project-revelare-web.pages.dev',
          'http://localhost:3000',
          'http://localhost:8080',
          'http://localhost:8000'
        ];

    // Allow requests from allowed origins or requests without origin (like mobile apps)
    if (allowedOrigins.includes(origin) || !origin) {
      return origin;
    }
    
    console.log('CORS: Rejected origin:', origin);
    console.log('CORS: Allowed origins:', allowedOrigins);
    return null;
  },
  allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  credentials: true,
  maxAge: 86400, // 24 hours
}));

// Handle preflight OPTIONS requests
app.options('*', (c) => {
  return c.text('OK', 200);
});

// Rate limiting (temporarily disabled - implement custom solution)
// app.use('*', rateLimiter({
//   windowMs: 60 * 1000, // 1 minute
//   limit: 100,
//   keyGenerator: (c) => {
//     return c.req.header('CF-Connecting-IP') || 'anonymous';
//   },
// }));

// Security headers middleware
app.use('*', async (c, next) => {
  await next();

  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;");

  // Add processing time
  const start = Date.now();
  c.header('X-Process-Time', `${Date.now() - start}ms`);
});

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: c.env.NODE_ENV || 'development',
    uptime: process.uptime ? `${Math.floor(process.uptime())}s` : 'unknown'
  });
});

// Root endpoint
app.get('/', (c) => {
  return c.json({
    name: 'Project Revelare API',
    description: 'Digital Forensics & Investigation Platform',
    version: '2.0.0',
    docs_url: '/docs',
    health_url: '/health',
    api_base: '/api/v1',
    features: [
      'JWT Authentication',
      'User Management',
      'Case Management',
      'Evidence Processing',
      'Analysis & Reporting',
      'File Upload & Storage'
    ]
  });
});

// API routes (no version prefix for compatibility)
const api = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    R2_EVIDENCE_BUCKET: R2Bucket;
    JWT_SECRET: string;
  };
}>();

// JWT middleware for protected routes
api.use('/auth/*', async (c, next) => {
  // Skip JWT for auth endpoints except logout
  if (c.req.path.includes('/logout')) {
    const jwtMiddleware = jwt({ secret: c.env.JWT_SECRET });
    return jwtMiddleware(c, next);
  }
  await next();
});

// Protected routes that require JWT
api.use('/*', async (c, next) => {
  // Skip JWT for public endpoints
  const publicPaths = ['/auth/login', '/auth/register', '/auth/refresh', '/me', '/health', '/', '/games'];
  const isPublicPath = publicPaths.some(path => c.req.path.includes(path));

  if (isPublicPath) {
    await next();
    return;
  }

  const jwtMiddleware = jwt({ secret: c.env.JWT_SECRET });
  await jwtMiddleware(c, next);
});

// Mount route handlers
api.route('/auth', authRoutes);
api.route('/admin/users', userRoutes);
api.route('/admin/cases', caseRoutes);
api.route('/admin/files', fileRoutes);
api.route('/news', newsRoutes);
// Games routes moved to main app for proper environment context
// api.route('/cases', caseRoutes);
// api.route('/evidence', evidenceRoutes);
// api.route('/analysis', analysisRoutes);

// Root endpoint for testing
app.get('/', (c) => {
  return c.json({ message: 'Project Revelare Backend is running!' });
});

// Test environment access
app.get('/api/test-env', async (c) => {
  try {
    console.log('Testing environment access...');
    console.log('Environment keys:', Object.keys(c.env));
    console.log('Environment:', c.env);
    
    return c.json({ 
      message: 'Environment test successful',
      hasEnv: !!c.env,
      envKeys: Object.keys(c.env),
      nodeEnv: c.env.NODE_ENV,
      apiVersion: c.env.API_VERSION,
      hasDB: !!c.env.DB
    });
  } catch (error) {
    console.error('Environment test error:', error);
    return c.json({ error: error.message }, 500);
  }
});

// Test auth functionality
app.get('/api/test-auth', async (c) => {
  try {
    console.log('Testing auth functionality...');
    
    // Test bcrypt
    const bcrypt = await import('bcryptjs');
    const testPassword = 'test123';
    const hashedPassword = await bcrypt.hash(testPassword, 10);
    const isValid = await bcrypt.compare(testPassword, hashedPassword);
    
    // Test JWT
    const { SignJWT } = await import('jose');
    const secret = new TextEncoder().encode(c.env.JWT_SECRET);
    const token = await new SignJWT({ userId: 'test' })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(secret);
    
    return c.json({
      message: 'Auth test successful',
      bcryptWorking: isValid,
      jwtWorking: !!token,
      hasJWTSecret: !!c.env.JWT_SECRET
    });
  } catch (error) {
    console.error('Auth test error:', error);
    return c.json({ error: error.message, stack: error.stack }, 500);
  }
});

// Test registration functionality
app.post('/api/test-register', async (c) => {
  try {
    console.log('Testing registration functionality...');
    
    const body = await c.req.json();
    const { email, password, firstName, lastName } = body;
    
    // Test bcrypt hashing
    const bcrypt = await import('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Test database insert
    const result = await c.env.DB.prepare(
      `INSERT INTO users (
        email, password_hash, firstName, lastName, access_tier, admin_level, 
        account_status, email_verified, mfa_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      email.toLowerCase(),
      passwordHash,
      firstName,
      lastName,
      'hobbyist',
      'none',
      'active',
      1,
      1
    ).run();
    
    return c.json({
      message: 'Registration test successful',
      success: result.success,
      changes: result.changes,
      meta: result.meta
    });
  } catch (error) {
    console.error('Registration test error:', error);
    return c.json({ 
      error: error.message, 
      stack: error.stack,
      name: error.name 
    }, 500);
  }
});

// Mount API (no version prefix for compatibility)
app.route('/api', api);

// Mount games routes directly on main app to ensure environment context
app.route('/api/games', gameRoutes);

// Add /me endpoint for user profile
api.get('/me', async (c) => {
  try {
    const payload = c.get('jwtPayload');

    const user = await c.env.DB.prepare(
      `SELECT id, email, first_name, last_name, agency, phone, access_tier, admin_level,
              account_status, email_verified, last_login_at, created_at
       FROM users WHERE id = ?`
    ).bind(payload.user_id).first();

    if (!user) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'User not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json({
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      agency: user.agency,
      phone: user.phone,
      access_tier: user.access_tier,
      admin_level: user.admin_level,
      account_status: user.account_status,
      email_verified: user.email_verified === 1,
      last_login: user.last_login_at,
      created_at: user.created_at
    });

  } catch (error) {
    console.error('Get user profile error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get user profile',
        status_code: 500
      }
    }, 500);
  }
});

// Add basic cases endpoint for regular users
api.get('/cases', async (c) => {
  try {
    const payload = c.get('jwtPayload');

    const cases = await c.env.DB.prepare(
      `SELECT c.id, c.case_number, c.title, c.description, c.status, c.priority,
              c.classification_level, c.created_by, c.created_at, c.total_files, c.total_size
       FROM cases c
       WHERE c.created_by = ? OR c.assigned_to = ?
       ORDER BY c.created_at DESC`
    ).bind(payload.user_id, payload.user_id).all();

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

// Add basic indicators endpoint
api.get('/indicators', async (c) => {
  try {
    // Get findings grouped by category
    const findings = await c.env.DB.prepare(
      `SELECT category, COUNT(*) as count, GROUP_CONCAT(DISTINCT value) as sample_values
       FROM findings
       GROUP BY category
       ORDER BY count DESC`
    ).all();

    const indicators = {};

    for (const finding of findings.results || []) {
      indicators[finding.category] = {
        count: finding.count,
        category: finding.category,
        sample_values: finding.sample_values ? finding.sample_values.split(',') : []
      };
    }

    return c.json({
      indicators: indicators,
      total_categories: Object.keys(indicators).length
    });

  } catch (error) {
    console.error('Get indicators error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get indicators',
        status_code: 500
      }
    }, 500);
  }
});

// Error handling
app.onError((err, c) => {
  console.error(`Error in ${c.req.method} ${c.req.path}:`, err);

  if (err.name === 'JWTError') {
    return c.json({
      error: {
        type: 'authentication_error',
        message: 'Invalid or expired token',
        status_code: 401
      }
    }, 401);
  }

  return c.json({
    error: {
      type: 'internal_server_error',
      message: `An unexpected error occurred: ${err.message}`,
      status_code: 500,
      details: err.toString()
    }
  }, 500);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: {
      type: 'not_found',
      message: 'The requested resource was not found',
      status_code: 404,
      path: c.req.path,
      method: c.req.method
    }
  }, 404);
});

// Main worker export
export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    // Pass environment bindings to Hono app
    return app.fetch(request, env, ctx);
  },

  // Scheduled handler for background tasks
  async scheduled(event: ScheduledEvent, env: any, ctx: ExecutionContext) {
    console.log('Scheduled task triggered:', event.cron);

    // Handle background tasks like:
    // - Cleaning up expired sessions
    // - Processing pending analysis jobs
    // - Generating reports
    // - Sending notifications

    switch (event.cron) {
      case '0 */6 * * *': // Every 6 hours
        await cleanupExpiredSessions(env);
        break;
      case '0 2 * * *': // Daily at 2 AM
        await generateDailyReports(env);
        break;
    }
  }
};

// Background task functions
async function cleanupExpiredSessions(env: any) {
  try {
    const { results } = await env.DB.prepare(
      "DELETE FROM user_sessions WHERE expires_at < datetime('now')"
    ).run();

    console.log(`Cleaned up ${results?.changes || 0} expired sessions`);
  } catch (error) {
    console.error('Error cleaning up sessions:', error);
  }
}

async function generateDailyReports(env: any) {
  try {
    // Generate daily activity reports
    console.log('Generating daily reports...');

    // This would implement report generation logic
    // For now, just log the task
  } catch (error) {
    console.error('Error generating daily reports:', error);
  }
}
