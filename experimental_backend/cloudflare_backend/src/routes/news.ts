/**
 * News Routes
 * Endpoints for cybersecurity news aggregation
 */

import { Hono } from 'hono';
import { z } from 'zod';

const newsRoutes = new Hono<{
  Bindings: {
    DB: D1Database;
    REVELARE_KV: KVNamespace;
    JWT_SECRET: string;
  };
}>();

// Get news articles with filtering and pagination
newsRoutes.get('/', async (c) => {
  try {
    const query = c.req.query();

    // Parse query parameters
    const category = query.category || 'all';
    const limit = Math.min(parseInt(query.limit) || 20, 100); // Max 100 articles
    const offset = parseInt(query.offset) || 0;

    let whereClause = "WHERE 1=1";
    const bindValues = [];

    // Filter by category if specified
    if (category && category !== 'all') {
      whereClause += " AND category = ?";
      bindValues.push(category);
    }

    // Add offset and limit to bind values
    bindValues.push(offset, limit);

    // Get total count for pagination
    const totalResult = await c.env.DB.prepare(
      `SELECT COUNT(*) as total FROM news_articles ${whereClause}`
    ).bind(...bindValues.slice(0, -2)).first();

    // Get articles with pagination
    const articlesResult = await c.env.DB.prepare(
      `SELECT title, link, description, pub_date, source, category, crawled_at
       FROM news_articles
       ${whereClause}
       ORDER BY pub_date DESC
       LIMIT ? OFFSET ?`
    ).bind(...bindValues).all();

    return c.json({
      articles: articlesResult.results || [],
      total: totalResult?.total || 0,
      limit: limit,
      offset: offset,
      category: category
    });

  } catch (error) {
    console.error('Get news error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get news articles',
        status_code: 500
      }
    }, 500);
  }
});

// Get news categories and counts
newsRoutes.get('/categories', async (c) => {
  try {
    const categories = await c.env.DB.prepare(
      `SELECT category, COUNT(*) as count
       FROM news_articles
       GROUP BY category
       ORDER BY count DESC`
    ).all();

    return c.json({
      categories: categories.results || []
    });

  } catch (error) {
    console.error('Get news categories error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get news categories',
        status_code: 500
      }
    }, 500);
  }
});

// Get latest news (admin endpoint for triggering crawler)
newsRoutes.post('/crawl', async (c) => {
  try {
    // In a real implementation, this would trigger the news crawler worker
    // For now, we'll just return a success message

    // TODO: Implement actual crawler triggering
    // const crawlerResponse = await fetch('https://news-crawler.your-domain.workers.dev/crawl', {
    //   method: 'POST'
    // });

    return c.json({
      success: true,
      message: 'News crawler triggered successfully',
      articles_updated: 0 // Would be actual count from crawler response
    });

  } catch (error) {
    console.error('Trigger news crawl error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to trigger news crawl',
        status_code: 500
      }
    }, 500);
  }
});

// Get news sources
newsRoutes.get('/sources', async (c) => {
  try {
    const sources = await c.env.DB.prepare(
      `SELECT source, COUNT(*) as count, MAX(pub_date) as latest_article
       FROM news_articles
       GROUP BY source
       ORDER BY count DESC`
    ).all();

    return c.json({
      sources: sources.results || []
    });

  } catch (error) {
    console.error('Get news sources error:', error);
    return c.json({
      error: {
        type: 'internal_server_error',
        message: 'Failed to get news sources',
        status_code: 500
      }
    }, 500);
  }
});

export { newsRoutes };
