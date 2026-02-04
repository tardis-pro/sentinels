import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'crypto';
import {
  processGitHubWebhook,
  deliverWebhook,
  createWebhookConfig,
  listWebhookConfigs,
  getWebhookConfig,
  updateWebhookConfig,
  deleteWebhookConfig,
  verifyGitHubSignature,
  recordGitHubInstallation,
  linkRepository,
  getInstallationRepos,
  connectWebhooksDb,
} from './service';

interface GitHubWebhookHeaders {
  'x-github-event': string;
  'x-github-delivery': string;
  'x-hub-signature-256'?: string;
  'x-github-hook-installation-target-id'?: string;
  'content-type': string;
}

interface CreateWebhookBody {
  name: string;
  endpointUrl: string;
  eventTypes: string[];
  description?: string;
  secret?: string;
  retryCount?: number;
  retryDelaySeconds?: number;
  timeoutSeconds?: number;
}

interface UpdateWebhookBody {
  name?: string;
  description?: string;
  endpoint_url?: string;
  event_types?: string[];
  is_active?: boolean;
  retry_count?: number;
  retry_delay_seconds?: number;
  timeout_seconds?: number;
}

export async function webhookRoutes(fastify: FastifyInstance) {
  // Ensure database connection
  fastify.addHook('onReady', async () => {
    await connectWebhooksDb();
  });

  // ============================================
  // INBOUND WEBHOOK ENDPOINTS
  // ============================================

  // GitHub App webhook receiver
  fastify.post<{
    Headers: GitHubWebhookHeaders;
    Body: Record<string, any>;
  }>('/webhooks/github', async (request: FastifyRequest<{ Headers: GitHubWebhookHeaders; Body: Record<string, any> }>, reply) => {
    try {
      const { 'x-github-event': eventType, 'x-github-delivery': deliveryId, 'x-hub-signature-256': signature } = request.headers;

      if (!eventType || !deliveryId) {
        return reply.status(400).send({ error: 'Missing required headers: x-github-event, x-github-delivery' });
      }

      // Get installation ID if present
      const installationId = request.headers['x-github-hook-installation-target-id'] || 'app';

      // Verify signature if webhook secret is configured
      const rawBody = JSON.stringify(request.body);
      const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET || 'development_secret';

      if (signature) {
        const isValid = verifyGitHubSignature(rawBody, signature, webhookSecret);
        if (!isValid) {
          fastify.log.warn('Invalid webhook signature');
          return reply.status(401).send({ error: 'Invalid signature' });
        }
      }

      const result = await processGitHubWebhook(
        installationId,
        deliveryId,
        eventType,
        request.body,
        request.headers as Record<string, string>
      );

      if (!result.success) {
        fastify.log.error(`Webhook processing failed: ${result.error}`);
        return reply.status(500).send({ error: result.error });
      }

      // Return 202 Accepted for async processing
      return reply.status(202).send({ received: true, eventId: result.eventId });
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Webhook processing failed' });
    }
  });

  // Generic webhook receiver (for testing/custom integrations)
  fastify.post<{
    Body: {
      provider: string;
      eventType: string;
      deliveryId: string;
      payload: Record<string, any>;
      signature?: string;
      secret?: string;
    };
  }>('/webhooks/generic', async (request, reply) => {
    try {
      const { provider, eventType, deliveryId, payload, signature, secret } = request.body;

      if (!provider || !eventType || !deliveryId || !payload) {
        return reply.status(400).send({ error: 'Missing required fields' });
      }

      // Store event in generic format
      const result = await processGitHubWebhook(
        'generic',
        deliveryId,
        `${provider}:${eventType}`,
        payload,
        { 'x-signature': signature || '' }
      );

      return reply.status(202).send({ received: true, eventId: result.eventId });
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Webhook processing failed' });
    }
  });

  // ============================================
  // OUTBOUND WEBHOOK MANAGEMENT
  // ============================================

  // List all webhook configurations
  fastify.get('/webhooks', async (request, reply) => {
    try {
      const webhooks = await listWebhookConfigs();
      return webhooks.map(wh => ({
        ...wh,
        secret: wh.secret ? '***hidden***' : null, // Don't return secrets
      }));
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to list webhooks' });
    }
  });

  // Create new webhook configuration
  fastify.post<{ Body: CreateWebhookBody }>('/webhooks', async (request, reply) => {
    try {
      const { name, endpointUrl, eventTypes, description, secret, retryCount, retryDelaySeconds, timeoutSeconds } = request.body;

      if (!name || !endpointUrl || !eventTypes || eventTypes.length === 0) {
        return reply.status(400).send({ error: 'Missing required fields: name, endpointUrl, eventTypes' });
      }

      const id = await createWebhookConfig(name, endpointUrl, eventTypes, 'system', {
        description,
        secret,
        retryCount,
        retryDelaySeconds,
        timeoutSeconds,
      });

      return reply.status(201).send({ id });
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to create webhook' });
    }
  });

  // Get webhook configuration
  fastify.get<{ Params: { id: string } }>('/webhooks/:id', async (request, reply) => {
    try {
      const webhook = await getWebhookConfig(request.params.id);
      if (!webhook) {
        return reply.status(404).send({ error: 'Webhook not found' });
      }
      return {
        ...webhook,
        secret: webhook.secret ? '***hidden***' : null,
      };
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to get webhook' });
    }
  });

  // Update webhook configuration
  fastify.patch<{ Params: { id: string }; Body: UpdateWebhookBody }>('/webhooks/:id', async (request, reply) => {
    try {
      const success = await updateWebhookConfig(request.params.id, request.body);
      if (!success) {
        return reply.status(404).send({ error: 'Webhook not found' });
      }
      return { success: true };
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to update webhook' });
    }
  });

  // Delete webhook configuration
  fastify.delete<{ Params: { id: string } }>('/webhooks/:id', async (request, reply) => {
    try {
      const success = await deleteWebhookConfig(request.params.id);
      if (!success) {
        return reply.status(404).send({ error: 'Webhook not found' });
      }
      return { success: true };
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to delete webhook' });
    }
  });

  // Test webhook delivery
  fastify.post<{ Params: { id: string }; Body: { eventType: string; testPayload?: Record<string, any> } }>(
    '/webhooks/:id/test',
    async (request, reply) => {
      try {
        const { eventType = 'test', testPayload = { message: 'Test webhook from Sentinel', timestamp: new Date().toISOString() } } = request.body;

        const result = await deliverWebhook(request.params.id, eventType, testPayload);
        return result;
      } catch (error) {
        fastify.log.error(error);
        return reply.status(500).send({ error: 'Failed to test webhook' });
      }
    }
  );

  // ============================================
  // GITHUB APP INSTALLATION
  // ============================================

  // Record GitHub App installation callback
  fastify.post<{ Body: { installationId: string; accountId: string; accountName: string; permissions: Record<string, any>; events: string[] } }>(
    '/webhooks/github/install',
    async (request, reply) => {
      try {
        const { installationId, accountId, accountName, permissions, events } = request.body;

        if (!installationId || !accountId) {
          return reply.status(400).send({ error: 'Missing installationId or accountId' });
        }

        const id = await recordGitHubInstallation(installationId, accountId, accountName, permissions, events);
        return { success: true, installationId: id };
      } catch (error) {
        fastify.log.error(error);
        return reply.status(500).send({ error: 'Failed to record installation' });
      }
    }
  );

  // Link repository to installation
  fastify.post<{ Body: { installationId: string; repoId: string; repoName: string; repoFullName: string; defaultBranch?: string } }>(
    '/webhooks/github/link-repo',
    async (request, reply) => {
      try {
        const { installationId, repoId, repoName, repoFullName, defaultBranch = 'main' } = request.body;

        if (!installationId || !repoId || !repoName || !repoFullName) {
          return reply.status(400).send({ error: 'Missing required fields' });
        }

        const id = await linkRepository(installationId, repoId, repoName, repoFullName, defaultBranch);
        return { success: true, linkId: id };
      } catch (error) {
        fastify.log.error(error);
        return reply.status(500).send({ error: 'Failed to link repository' });
      }
    }
  );

  // List linked repositories for installation
  fastify.get<{ Params: { installationId: string } }>('/webhooks/github/install/:installationId/repos', async (request, reply) => {
    try {
      const repos = await getInstallationRepos(request.params.installationId);
      return repos;
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to list repositories' });
    }
  });

  // ============================================
  // DELIVERY STATUS
  // ============================================

  // Get delivery statistics
  fastify.get('/webhooks/stats', async (request, reply) => {
    try {
      const { getDeliveryStats } = await import('./service');
      const stats = await getDeliveryStats();
      return stats;
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to get stats' });
    }
  });
}
