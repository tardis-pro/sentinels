import crypto from 'crypto';
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { createGitProviderClient } from './index';
import { 
  createWebhookConfig, 
  getWebhookConfigs, 
  updateWebhookConfig, 
  deleteWebhookConfig,
  createScanTrigger,
  getPendingTriggers,
  updateScanTriggerStatus,
  saveGitProviderConfig,
  getGitProviderConfig,
  decryptSecret,
  encryptSecret,
  processGitHubWebhook,
  deliverWebhook,
  listWebhookConfigs,
  getWebhookConfig,
  verifyGitHubSignature,
  recordGitHubInstallation,
  linkRepository,
  getInstallationRepos,
  connectWebhooksDb,
} from './service';
import { WebhookDelivery, ScanTrigger } from './types';
import { scannerQueue } from '../queue';
import { getProjectById, createScan, createScanRun } from '../db';
import { SupportedScanner } from '../parsers';

// Simple encryption for secrets
const ENCRYPTION_KEY = process.env.SENTINEL_ENCRYPTION_KEY || 'default-key-32-bytes-long!!';
const IV_LENGTH = 16;

function encrypt(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY.padEnd(32)), iv);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text: string): string {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY.padEnd(32)), iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString('utf8');
}

// Validate URL to prevent SSRF attacks
function isValidApiUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    const hostname = parsed.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1' || 
        hostname === '0.0.0.0' || hostname === '::1') return false;
    if (/^10\.\d+\.\d+\.\d+$/.test(hostname)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(hostname)) return false;
    if (/^192\.168\.\d+\.\d+$/.test(hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

interface GitHubWebhookHeaders {
  'x-github-event': string;
  'x-github-delivery': string;
  'x-hub-signature-256'?: string;
  'x-github-hook-installation-target-id'?: string;
  'content-type': string;
}

export async function webhookRoutes(fastify: FastifyInstance): Promise<void> {
  // Ensure database connection
  fastify.addHook('onReady', async () => {
    await connectWebhooksDb();
  });

  // ============================================
  // INBOUND WEBHOOK ENDPOINTS (PR #14)
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
  // OUTBOUND WEBHOOK MANAGEMENT (PR #14)
  // ============================================

  // List all webhook configurations
  fastify.get('/webhooks', async (request, reply) => {
    try {
      const webhooks = await listWebhookConfigs();
      return webhooks.map(wh => ({
        ...wh,
        secret: wh.secret ? '***hidden***' : null,
      }));
    } catch (error) {
      fastify.log.error(error);
      return reply.status(500).send({ error: 'Failed to list webhooks' });
    }
  });

  // Create new webhook configuration
  fastify.post('/webhooks', async (request, reply) => {
    try {
      const body = request.body as { name?: string; endpointUrl?: string; eventTypes?: string[]; description?: string; secret?: string };
      const { name, endpointUrl, eventTypes, description, secret } = body;

      if (!name || !endpointUrl || !eventTypes || eventTypes.length === 0) {
        return reply.status(400).send({ error: 'Missing required fields: name, endpointUrl, eventTypes' });
      }

      const id = await createWebhookConfig(name, endpointUrl, eventTypes, 'system', {
        description,
        secret,
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
  fastify.patch<{ Params: { id: string } }>('/webhooks/:id', async (request, reply) => {
    try {
      const updates = request.body as Record<string, any>;
      const success = await updateWebhookConfig(request.params.id, updates);
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
  fastify.post<{ Params: { id: string }; Body: { eventType?: string; testPayload?: Record<string, any> } }>(
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

  // ============================================
  // GIT PROVIDER CONFIGURATION (PR #17)
  // ============================================

  fastify.post('/git/providers', async (request, reply) => {
    const body = request.body as { projectId?: string; provider?: string; apiUrl?: string; token?: string; webhookSecret?: string };
    const { projectId, provider, apiUrl, token, webhookSecret } = body;

    if (!projectId || !provider || !token) {
      reply.status(400).send({ error: 'Missing required fields' });
      return;
    }

    if (apiUrl && !isValidApiUrl(apiUrl)) {
      reply.status(400).send({ error: 'Invalid API URL' });
      return;
    }

    await saveGitProviderConfig({
      projectId,
      provider,
      apiUrl,
      token: encrypt(token),
      webhookSecret: webhookSecret ? encrypt(webhookSecret) : undefined,
    });

    reply.status(201).send({ message: 'Provider configured successfully' });
  });

  fastify.get('/projects/:id/git/provider', async (request, reply) => {
    const { id } = request.params as { id: string };
    const config = await getGitProviderConfig(id);
    reply.send(config ? { configured: true, provider: config.provider } : { configured: false });
  });

  // ============================================
  // SCAN TRIGGER MANAGEMENT (PR #17)
  // ============================================

  fastify.get('/scan-triggers', async (request, reply) => {
    const { projectId, status } = request.query as { projectId?: string; status?: string };
    const triggers = await getPendingTriggers(projectId);
    reply.send(triggers);
  });

  fastify.patch('/scan-triggers/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { status, startedAt, completedAt } = request.body as { status?: string; startedAt?: Date; completedAt?: Date };
    await updateScanTriggerStatus(id, status, startedAt, completedAt);
    reply.send({ message: 'Trigger updated' });
  });

  // Trigger a scan manually or via webhook
  fastify.post('/scans/trigger', async (request, reply) => {
    const body = request.body as { projectId?: string; scanners?: string[]; triggerType?: string; source?: string; branch?: string; commitSha?: string; prNumber?: number };
    const { projectId, scanners, triggerType, source, branch, commitSha, prNumber } = body;

    if (!projectId || !scanners?.length) {
      reply.status(400).send({ error: 'Missing required fields' });
      return;
    }

    const trigger = await createScanTrigger({
      projectId,
      triggerType: triggerType || 'manual',
      source: source || 'manual',
      branch,
      commitSha,
      prNumber,
      config: {
        scanners,
        diffMode: false,
        autoScan: true,
        failOnCritical: false,
      },
    });

    const project = await getProjectById(projectId);
    if (!project) {
      reply.status(404).send({ error: 'Project not found' });
      return;
    }

    const scanRecord = await createScan(projectId, scanners as SupportedScanner[]);

    for (const scannerType of scanners) {
      const run = await createScanRun(scanRecord.id, scannerType);
      await scannerQueue.add('scan-job', {
        scanId: scanRecord.id,
        scanRunId: run.id,
        hostPath: project.path,
        scannerType,
      });
    }

    reply.status(202).send({
      trigger,
      scan: scanRecord,
    });
  });
}
