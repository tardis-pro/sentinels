import { FastifyInstance } from 'fastify';
import { getAIAnalysisService } from '../ai/service';
import { FindingContext } from '../ai/types';

// AI Analysis routes
export async function aiRoutes(fastify: FastifyInstance): Promise<void> {
  const aiService = getAIAnalysisService();

  // Get AI service status
  fastify.get('/ai/status', async (request, reply) => {
    try {
      const status = await aiService.getStatus();
      return status;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'AI service unavailable' });
    }
  });

  // Analyze a finding
  fastify.post('/ai/analyze', async (request, reply) => {
    const context = request.body as FindingContext;
    
    if (!context.ruleId || !context.filePath || !context.severity) {
      reply.status(400).send({ 
        error: 'Missing required fields: ruleId, filePath, severity' 
      });
      return;
    }

    try {
      const result = await aiService.analyzeFinding(context);
      return result;
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ 
        error: 'Analysis failed', 
        message: error instanceof Error ? error.message : 'Unknown error' 
      });
    }
  });

  // Batch analyze findings
  fastify.post('/ai/analyze-batch', async (request, reply) => {
    const { findings } = request.body as { findings: FindingContext[] };
    
    if (!Array.isArray(findings)) {
      reply.status(400).send({ error: 'Findings must be an array' });
      return;
    }

    try {
      const results = await aiService.analyzeFindings(findings);
      return { 
        total: findings.length,
        analyzed: results.size,
        results: Array.from(results.entries()).map(([ruleId, result]) => ({
          ruleId,
          ...result,
        })),
      };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ 
        error: 'Batch analysis failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Find similar findings
  fastify.post('/ai/similar', async (request, reply) => {
    const { finding, projectId, limit } = request.body as {
      finding: FindingContext;
      projectId: string;
      limit?: number;
    };

    if (!projectId) {
      reply.status(400).send({ error: 'projectId is required' });
      return;
    }

    try {
      const similar = await aiService.findSimilarFindings(finding, projectId, limit || 5);
      return { similarFindings: similar };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Similarity search failed' });
    }
  });

  // Generate embeddings for findings
  fastify.post('/ai/embeddings', async (request, reply) => {
    const { findings } = request.body as { findings: FindingContext[] };

    try {
      const embeddings = await Promise.all(
        findings.map(f => aiService.generateEmbedding(f))
      );
      return { embeddings };
    } catch (error) {
      fastify.log.error(error);
      reply.status(500).send({ error: 'Embedding generation failed' });
    }
  });

  // Clear AI cache
  fastify.post('/ai/cache/clear', async (request, reply) => {
    aiService.clearCache();
    return { message: 'Cache cleared successfully' };
  });

  // Chat interface for conversational analysis
  fastify.post('/ai/chat', async (request, reply) => {
    const { sessionId, message, findingContext } = request.body as {
      sessionId?: string;
      message: string;
      findingContext?: FindingContext;
    };

    if (!sessionId && !findingContext) {
      reply.status(400).send({ 
        error: 'Either sessionId or findingContext is required' 
      });
      return;
    }

    return {
      sessionId: sessionId || crypto.randomUUID(),
      response: `I understand you're asking about: ${message}`,
      suggestion: 'For detailed analysis, use the /ai/analyze endpoint with full finding context.',
    };
  });

  // Submit feedback on AI analysis
  fastify.post('/ai/feedback', async (request, reply) => {
    const feedback = request.body as {
      analysisId: string;
      type: string;
      rating?: number;
      comment?: string;
      wasAccurate?: boolean;
      suggestionWasHelpful?: boolean;
    };

    if (!feedback.analysisId || !feedback.type) {
      reply.status(400).send({ 
        error: 'Missing required fields: analysisId, type' 
      });
      return;
    }

    fastify.log.info({ feedback }, 'AI feedback received');
    
    return { message: 'Feedback recorded successfully' };
  });
}
