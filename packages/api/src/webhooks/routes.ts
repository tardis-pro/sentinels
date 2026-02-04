import crypto from 'crypto';
import { FastifyInstance } from 'fastify';
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
} from './db';
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

export async function webhookRoutes(fastify: FastifyInstance): Promise<void> {
  // Webhook configuration endpoints
  fastify.post('/webhooks', async (request, reply) => {
    const body = request.body as { projectId?: string; provider?: string; events?: string[]; url?: string; secret?: string };
    const { projectId, provider, events, url, secret } = body;

    if (!projectId || !provider || !url) {
      reply.status(400).send({ error: 'Missing required fields' });
      return;
    }

    const webhook = await createWebhookConfig({
      projectId,
      provider,
      events: events || ['push', 'pull_request'],
      url,
      secret: secret || crypto.randomUUID(),
    });

    reply.status(201).send(webhook);
  });

  fastify.get('/projects/:id/webhooks', async (request, reply) => {
    const { id } = request.params as { id: string };
    const webhooks = await getWebhookConfigs(id);
    reply.send(webhooks);
  });

  fastify.patch('/webhooks/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const updates = request.body as Partial<{ events: string[]; url: string; enabled: boolean; secret: string }>;
    const webhook = await updateWebhookConfig(id, updates);
    
    if (!webhook) {
      reply.status(404).send({ error: 'Webhook not found' });
      return;
    }
    
    reply.send(webhook);
  });

  fastify.delete('/webhooks/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    await deleteWebhookConfig(id);
    reply.status(204).send();
  });

  // Git provider configuration
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

  // Scan trigger management
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
