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
} from './db';
import { WebhookDelivery, ScanTrigger } from './types';
import { scannerQueue } from '../queue';
import { getProjectById, createScan, createScanRun } from '../db';
import { SupportedScanner } from '../parsers';

export async function webhookRoutes(fastify: FastifyInstance): Promise<void> {
  // Webhook configuration endpoints
  fastify.post('/webhooks', async (request, reply) => {
    const { projectId, provider, events, url, secret } = request.body as any;

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
    const updates = request.body as any;
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
    const { projectId, provider, apiUrl, token, webhookSecret } = request.body as any;

    if (!projectId || !provider || !token) {
      reply.status(400).send({ error: 'Missing required fields' });
      return;
    }

    await saveGitProviderConfig({
      projectId,
      provider,
      apiUrl,
      token,
      webhookSecret,
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
    const { projectId, status } = request.query as any;
    const triggers = await getPendingTriggers(projectId);
    reply.send(triggers);
  });

  fastify.patch('/scan-triggers/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { status, startedAt, completedAt } = request.body as any;
    await updateScanTriggerStatus(id, status, startedAt, completedAt);
    reply.send({ message: 'Trigger updated' });
  });

  // Trigger a scan manually or via webhook
  fastify.post('/scans/trigger', async (request, reply) => {
    const { projectId, scanners, triggerType, source, branch, commitSha, prNumber } = request.body as any;

    if (!projectId || !scanners?.length) {
      reply.status(400).send({ error: 'Missing required fields' });
      return;
    }

    // Create trigger record
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

    // Start the scan
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
