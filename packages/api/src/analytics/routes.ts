import { FastifyInstance } from 'fastify';
import {
  getAnalyticsSummary,
  getFindingTrends,
  getProjectScores,
  getScannerPerformance,
  getComplianceSummary,
  refreshMaterializedViews,
  getSecurityPostureHistory,
  getFindingDensityByType,
  getRemediationVelocity,
  trackAnalyticsEvent,
  connectAnalyticsDb,
} from './service';

export async function analyticsRoutes(fastify: FastifyInstance) {
  // Ensure database connection on startup
  fastify.addHook('onReady', async () => {
    await connectAnalyticsDb();
  });

  // GET /api/analytics/summary - Get overall analytics summary
  fastify.get<{
    Querystring: {
      projectId?: string;
      startDate?: string;
      endDate?: string;
    };
  }>('/analytics/summary', async (request, reply) => {
    try {
      const { projectId, startDate, endDate } = request.query;
      const summary = await getAnalyticsSummary(
        projectId,
        startDate || endDate ? { start: startDate, end: endDate } : undefined
      );
      return summary;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get analytics summary' });
    }
  });

  // GET /api/analytics/trends - Get finding trends
  fastify.get<{
    Querystring: {
      interval?: 'day' | 'week' | 'month';
      projectId?: string;
      startDate?: string;
      endDate?: string;
    };
  }>('/analytics/trends', async (request, reply) => {
    try {
      const { interval = 'day', projectId, startDate, endDate } = request.query;
      const trends = await getFindingTrends(
        interval,
        startDate || endDate ? { start: startDate, end: endDate } : undefined,
        projectId
      );
      return trends;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get finding trends' });
    }
  });

  // GET /api/analytics/projects - Get project security scores
  fastify.get<{
    Querystring: {
      limit?: number;
    };
  }>('/analytics/projects', async (request, reply) => {
    try {
      const limit = Number(request.query.limit ?? 10);
      const scores = await getProjectScores(limit);
      return scores;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get project scores' });
    }
  });

  // GET /api/analytics/scanners - Get scanner performance metrics
  fastify.get('/analytics/scanners', async (request, reply) => {
    try {
      const performance = await getScannerPerformance();
      return performance;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get scanner performance' });
    }
  });

  // GET /api/analytics/compliance - Get compliance summary
  fastify.get<{
    Querystring: {
      framework?: string;
    };
  }>('/analytics/compliance', async (request, reply) => {
    try {
      const framework = request.query.framework || 'OWASP Top 10';
      const compliance = await getComplianceSummary(framework);
      return compliance;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get compliance summary' });
    }
  });

  // GET /api/analytics/posture-history - Get security posture over time
  fastify.get<{
    Querystring: {
      days?: number;
    };
  }>('/analytics/posture-history', async (request, reply) => {
    try {
      const days = Number(request.query.days ?? 30);
      const history = await getSecurityPostureHistory(days);
      return history;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get posture history' });
    }
  });

  // GET /api/analytics/finding-density - Get findings by type
  fastify.get('/analytics/finding-density', async (request, reply) => {
    try {
      const density = await getFindingDensityByType();
      return density;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get finding density' });
    }
  });

  // GET /api/analytics/remediation-velocity - Get remediation velocity
  fastify.get<{
    Querystring: {
      days?: number;
    };
  }>('/analytics/remediation-velocity', async (request, reply) => {
    try {
      const days = Number(request.query.days ?? 30);
      const velocity = await getRemediationVelocity(days);
      return velocity;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to get remediation velocity' });
    }
  });

  // POST /api/analytics/refresh - Refresh materialized views (admin only)
  fastify.post('/analytics/refresh', async (request, reply) => {
    try {
      await refreshMaterializedViews();
      return { success: true, message: 'Materialized views refreshed' };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to refresh materialized views' });
    }
  });

  // POST /api/analytics/track - Track analytics event
  fastify.post<{
    Body: {
      eventType: string;
      projectId?: string;
      scanId?: string;
      metricName: string;
      metricValue: number;
      dimensions?: Record<string, any>;
    };
  }>('/analytics/track', async (request, reply) => {
    try {
      const { eventType, projectId, scanId, metricName, metricValue, dimensions } = request.body;
      await trackAnalyticsEvent(eventType, projectId || null, scanId || null, metricName, metricValue, dimensions || {});
      return { success: true };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Failed to track analytics event' });
    }
  });
}
