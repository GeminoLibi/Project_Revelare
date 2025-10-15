/**
 * File Management Routes (Admin)
 * Endpoints for file administration
 */

import { Hono } from 'hono';

const fileRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Get all files (admin only)
fileRoutes.get('/', async (c) => {
  try {
    const files = await c.env.DB.prepare(
      `SELECT ef.id, ef.case_id, ef.file_path, ef.original_filename, ef.file_size,
              ef.mime_type, ef.file_type, ef.status, ef.uploaded_by, ef.created_at,
              c.case_number, c.title as case_title,
              u.first_name, u.last_name, u.email as uploader_email
       FROM evidence_files ef
       LEFT JOIN cases c ON ef.case_id = c.id
       LEFT JOIN users u ON ef.uploaded_by = u.id
       ORDER BY ef.created_at DESC`
    ).all();

    return c.json({
      files: files.results || [],
      total: files.results?.length || 0
    });

  } catch (error) {
    console.error('Get files error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get files',
        status_code: 500
      }
    }, 500);
  }
});

// Get files for a specific case (admin only)
fileRoutes.get('/case/:caseId', async (c) => {
  try {
    const caseId = c.req.param('caseId');

    const files = await c.env.DB.prepare(
      `SELECT ef.id, ef.file_path, ef.original_filename, ef.file_size,
              ef.mime_type, ef.file_type, ef.status, ef.uploaded_by, ef.created_at,
              u.first_name, u.last_name, u.email as uploader_email
       FROM evidence_files ef
       LEFT JOIN users u ON ef.uploaded_by = u.id
       WHERE ef.case_id = ?
       ORDER BY ef.created_at DESC`
    ).bind(caseId).all();

    return c.json({
      files: files.results || [],
      total: files.results?.length || 0
    });

  } catch (error) {
    console.error('Get case files error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get case files',
        status_code: 500
      }
    }, 500);
  }
});

// Get file by ID (admin only)
fileRoutes.get('/:fileId', async (c) => {
  try {
    const fileId = c.req.param('fileId');

    const file = await c.env.DB.prepare(
      `SELECT ef.id, ef.case_id, ef.file_path, ef.original_filename, ef.file_size,
              ef.mime_type, ef.file_type, ef.status, ef.virus_scan_result,
              ef.is_malicious, ef.uploaded_by, ef.created_at,
              c.case_number, c.title as case_title,
              u.first_name, u.last_name, u.email as uploader_email
       FROM evidence_files ef
       LEFT JOIN cases c ON ef.case_id = c.id
       LEFT JOIN users u ON ef.uploaded_by = u.id
       WHERE ef.id = ?`
    ).bind(fileId).first();

    if (!file) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'File not found',
          status_code: 404
        }
      }, 404);
    }

    return c.json(file);

  } catch (error) {
    console.error('Get file error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get file',
        status_code: 500
      }
    }, 500);
  }
});

// Delete file (admin only)
fileRoutes.delete('/:fileId', async (c) => {
  try {
    const fileId = c.req.param('fileId');

    // Check if file exists
    const file = await c.env.DB.prepare(
      "SELECT id, file_path FROM evidence_files WHERE id = ?"
    ).bind(fileId).first();

    if (!file) {
      return c.json({
        error: {
          type: 'not_found',
          message: 'File not found',
          status_code: 404
        }
      }, 404);
    }

    // Delete file record (R2 file deletion would need to be implemented separately)
    await c.env.DB.prepare("DELETE FROM evidence_files WHERE id = ?").bind(fileId).run();

    return c.json({
      success: true,
      message: 'File deleted successfully'
    });

  } catch (error) {
    console.error('Delete file error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to delete file',
        status_code: 500
      }
    }, 500);
  }
});

export { fileRoutes };
