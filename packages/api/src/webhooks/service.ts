import crypto from 'crypto';
import { Client } from 'pg';

const client = new Client({
  connectionString: process.env.DATABASE_URL || 'postgres://sentinel:sentinel@localhost:35432/sentinel',
});

let webhooksConnected = false;
let webhooksConnectPromise: Promise<void> | null = null;

async function ensureWebhookServiceTables() {
  await client.query(`
    CREATE TABLE IF NOT EXISTS webhook_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      installation_id TEXT,
      event_type TEXT NOT NULL,
      delivery_id TEXT UNIQUE NOT NULL,
      payload JSONB NOT NULL,
      headers JSONB,
      processing_status TEXT NOT NULL DEFAULT 'received',
      error_message TEXT,
      processed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS webhook_installations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      provider TEXT NOT NULL,
      installation_id TEXT NOT NULL,
      account_id TEXT,
      account_name TEXT,
      permissions JSONB,
      events TEXT[] DEFAULT '{}',
      auto_scan BOOLEAN DEFAULT true,
      scan_on_push BOOLEAN DEFAULT true,
      scan_on_pr BOOLEAN DEFAULT true,
      branch_pattern TEXT DEFAULT '.*',
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(provider, installation_id)
    );

    CREATE TABLE IF NOT EXISTS webhook_repo_links (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      installation_id TEXT NOT NULL,
      repo_id TEXT NOT NULL,
      repo_name TEXT,
      repo_full_name TEXT,
      default_branch TEXT DEFAULT 'main',
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(installation_id, repo_id)
    );

    CREATE TABLE IF NOT EXISTS analytics_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      event_type TEXT NOT NULL,
      project_id UUID,
      scan_id UUID,
      metric_name TEXT NOT NULL,
      metric_value DOUBLE PRECISION NOT NULL DEFAULT 0,
      dimensions JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS webhook_config_id UUID;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS event_type TEXT;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS response_status INT;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS response_headers JSONB;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS error_message TEXT;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
    ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
    ALTER TABLE webhook_deliveries ALTER COLUMN webhook_id DROP NOT NULL;

    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS name TEXT;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS endpoint_url TEXT;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS event_types TEXT[] DEFAULT '{}';
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS retry_count INT DEFAULT 3;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS retry_delay_seconds INT DEFAULT 60;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS timeout_seconds INT DEFAULT 30;
    ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS created_by TEXT;
    ALTER TABLE webhook_configs ALTER COLUMN secret DROP NOT NULL;

    UPDATE webhook_configs
    SET endpoint_url = COALESCE(endpoint_url, url),
        event_types = COALESCE(event_types, events),
        is_active = COALESCE(is_active, enabled, true)
    WHERE endpoint_url IS NULL OR event_types IS NULL OR is_active IS NULL;

    UPDATE webhook_deliveries
    SET webhook_config_id = COALESCE(webhook_config_id, webhook_id),
        event_type = COALESCE(event_type, event),
        response_status = COALESCE(response_status, response_code)
    WHERE webhook_config_id IS NULL OR event_type IS NULL OR response_status IS NULL;

    CREATE INDEX IF NOT EXISTS idx_webhook_events_delivery_id ON webhook_events(delivery_id);
    CREATE INDEX IF NOT EXISTS idx_webhook_installations_lookup ON webhook_installations(provider, installation_id);
    CREATE INDEX IF NOT EXISTS idx_webhook_repo_links_repo_id ON webhook_repo_links(repo_id);
  `);
}

interface WebhookConfig {
  id: string;
  name: string;
  endpoint_url: string;
  secret: string | null;
  event_types: string[];
  is_active: boolean;
  retry_count: number;
  retry_delay_seconds: number;
  timeout_seconds: number;
}

interface WebhookEvent {
  id: string;
  installation_id: string | null;
  event_type: string;
  delivery_id: string;
  payload: Record<string, any>;
  processing_status: string;
}

export async function connectWebhooksDb() {
  if (webhooksConnected) {
    return;
  }
  if (webhooksConnectPromise) {
    await webhooksConnectPromise;
    return;
  }

  webhooksConnectPromise = client
    .connect()
    .then(async () => {
      await ensureWebhookServiceTables();
      webhooksConnected = true;
      console.log('Connected to PostgreSQL for webhooks');
    })
    .catch((error) => {
      webhooksConnectPromise = null;
      throw error;
    });

  await webhooksConnectPromise;
}

// ============================================
// INBOUND WEBHOOK HANDLERS
// ============================================

export async function processGitHubWebhook(
  installationId: string,
  deliveryId: string,
  eventType: string,
  payload: Record<string, any>,
  headers: Record<string, string>
): Promise<{ success: boolean; eventId?: string; error?: string }> {
  try {
    // Store the webhook event
    const result = await client.query(
      `INSERT INTO webhook_events 
       (installation_id, event_type, delivery_id, payload, headers, processing_status)
       VALUES ($1, $2, $3, $4, $5, 'received')
       ON CONFLICT (delivery_id) DO NOTHING
       RETURNING id`,
      [installationId, eventType, deliveryId, JSON.stringify(payload), JSON.stringify(headers)]
    );

    if (result.rows.length === 0) {
      return { success: true, eventId: 'duplicate' };
    }

    const eventId = result.rows[0].id;

    // Process based on event type
    await processWebhookEvent(eventId, eventType, payload);

    return { success: true, eventId };
  } catch (error) {
    console.error('Failed to process GitHub webhook:', error);
    return { success: false, error: String(error) };
  }
}

async function processWebhookEvent(eventId: string, eventType: string, payload: Record<string, any>) {
  // Update status to processing
  await client.query(
    `UPDATE webhook_events SET processing_status = 'processing' WHERE id = $1`,
    [eventId]
  );

  try {
    switch (eventType) {
      case 'push':
        await handlePushEvent(eventId, payload);
        break;
      case 'pull_request':
        await handlePullRequestEvent(eventId, payload);
        break;
      case 'ping':
        await handlePingEvent(eventId, payload);
        break;
      default:
        // Mark as ignored for unhandled events
        await client.query(
          `UPDATE webhook_events SET processing_status = 'ignored' WHERE id = $1`,
          [eventId]
        );
    }

    // Mark as completed
    await client.query(
      `UPDATE webhook_events SET processing_status = 'completed', processed_at = NOW() WHERE id = $1`,
      [eventId]
    );
  } catch (error) {
    await client.query(
      `UPDATE webhook_events SET processing_status = 'failed', error_message = $2 WHERE id = $1`,
      [eventId, String(error)]
    );
  }
}

async function handlePushEvent(eventId: string, payload: any) {
  // Extract repository info
  const repo = payload.repository;
  if (!repo) return;

  const repoId = String(repo.id);
  const branch = payload.ref?.replace('refs/heads/', '') || 'main';

  // Check if project is linked to this repository
  const linkResult = await client.query(
    `SELECT pl.*, pi.auto_scan, pi.scan_on_push, pi.branch_pattern
     FROM webhook_repo_links pl
     JOIN webhook_installations pi ON pi.id = pl.installation_id
     WHERE pl.repo_id = $1 AND pl.is_active = TRUE AND pi.is_active = TRUE`,
    [repoId]
  );

  if (linkResult.rows.length === 0) return;

  const link = linkResult.rows[0];

  // Check branch pattern
  const branchRegex = new RegExp(link.branch_pattern);
  if (!branchRegex.test(branch)) return;

  if (!link.scan_on_push) return;

  // TODO: Trigger scan via existing scanner queue
  console.log(`Push detected for ${repo.full_name}:${branch} - would trigger scan`);

  // Track analytics event
  await client.query(
    `INSERT INTO analytics_events (event_type, metric_name, metric_value, dimensions)
     VALUES ('webhook', 'push_event', 1, $1)`,
    [JSON.stringify({ repo: repo.full_name, branch })]
  );
}

async function handlePullRequestEvent(eventId: string, payload: any) {
  const repo = payload.repository;
  const pr = payload.pull_request;
  if (!repo || !pr) return;

  const repoId = String(repo.id);
  const action = payload.action; // opened, synchronize, closed, etc.

  const linkResult = await client.query(
    `SELECT pl.*, pi.auto_scan, pi.scan_on_pr, pi.branch_pattern
     FROM webhook_repo_links pl
     JOIN webhook_installations pi ON pi.id = pl.installation_id
     WHERE pl.repo_id = $1 AND pl.is_active = TRUE AND pi.is_active = TRUE`,
    [repoId]
  );

  if (linkResult.rows.length === 0) return;

  const link = linkResult.rows[0];

  if (!link.scan_on_pr) return;
  if (action !== 'opened' && action !== 'synchronize') return;

  const headBranch = pr.head?.ref;
  const baseBranch = pr.base?.ref;

  if (!headBranch || !baseBranch) return;

  // TODO: Trigger PR scan with diff analysis
  console.log(`PR #${pr.number} (${headBranch} -> ${baseBranch}) - would trigger scan`);

  await client.query(
    `INSERT INTO analytics_events (event_type, metric_name, metric_value, dimensions)
     VALUES ('webhook', 'pr_event', 1, $1)`,
    [JSON.stringify({ repo: repo.full_name, pr: pr.number, action })]
  );
}

async function handlePingEvent(eventId: string, payload: any) {
  console.log('Received ping event from GitHub App:', payload.zen);
  await client.query(
    `INSERT INTO analytics_events (event_type, metric_name, metric_value, dimensions)
     VALUES ('webhook', 'ping_event', 1, $1)`,
    [JSON.stringify({ zen: payload.zen })]
  );
}

// ============================================
// OUTBOUND WEBHOOK DELIVERY
// ============================================

export async function deliverWebhook(
  webhookConfigId: string,
  eventType: string,
  payload: Record<string, any>
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  const configResult = await client.query(
    'SELECT * FROM webhook_configs WHERE id = $1 AND is_active = TRUE',
    [webhookConfigId]
  );

  if (configResult.rows.length === 0) {
    return { success: false, error: 'Webhook config not found or inactive' };
  }

  const config = configResult.rows[0] as WebhookConfig;

  // Check if this event type is subscribed
  if (!config.event_types.includes(eventType) && !config.event_types.includes('*')) {
    return { success: false, error: 'Event type not subscribed' };
  }

  // Create delivery record
  const deliveryResult = await client.query(
    `INSERT INTO webhook_deliveries (webhook_config_id, event_type, payload, status)
     VALUES ($1, $2, $3, 'pending')
     RETURNING id`,
    [webhookConfigId, eventType, JSON.stringify(payload)]
  );

  const deliveryId = deliveryResult.rows[0].id;

  try {
    // Sign payload if secret is configured
    const payloadString = JSON.stringify(payload);
    const signature = config.secret
      ? `sha256=${crypto.createHmac('sha256', config.secret).update(payloadString).digest('hex')}`
      : undefined;

    // Deliver webhook
    const response = await fetch(config.endpoint_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Event': eventType,
        'X-Sentinel-Delivery': deliveryId,
        ...(signature && { 'X-Sentinel-Signature': signature }),
      },
      body: payloadString,
    });

    const responseText = await response.text();
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    // Update delivery record
    await client.query(
      `UPDATE webhook_deliveries SET 
        status = $1, 
        response_status = $2,
        response_headers = $3,
        response_body = $4,
        completed_at = NOW()
       WHERE id = $5`,
      [
        response.ok ? 'sent' : 'failed',
        response.status,
        JSON.stringify(responseHeaders),
        responseText.slice(0, 10000), // Limit response body size
        deliveryId,
      ]
    );

    if (!response.ok) {
      return { success: false, statusCode: response.status, error: `HTTP ${response.status}` };
    }

    return { success: true, statusCode: response.status };
  } catch (error) {
    // Mark as failed and schedule retry
    await client.query(
      `UPDATE webhook_deliveries SET 
        status = 'retrying',
        error_message = $2,
        attempts = attempts + 1,
        next_retry_at = NOW() + INTERVAL '${config.retry_delay_seconds} seconds'
       WHERE id = $1`,
      [deliveryId, String(error)]
    );

    return { success: false, error: String(error) };
  }
}

export async function retryFailedDeliveries(): Promise<void> {
  // Get failed deliveries eligible for retry
  const result = await client.query(
    `SELECT * FROM webhook_deliveries 
     WHERE status = 'retrying' 
     AND attempts < (SELECT retry_count FROM webhook_configs WHERE id = webhook_config_id)
     AND next_retry_at <= NOW()`
  );

  for (const delivery of result.rows) {
    const payload = JSON.parse(delivery.payload);
    const configResult = await client.query(
      'SELECT * FROM webhook_configs WHERE id = $1',
      [delivery.webhook_config_id]
    );

    if (configResult.rows.length === 0) {
      await client.query(
        `UPDATE webhook_deliveries SET status = 'failed', error_message = 'Config not found' WHERE id = $1`,
        [delivery.id]
      );
      continue;
    }

    const config = configResult.rows[0] as WebhookConfig;

    if (delivery.attempts >= config.retry_count) {
      await client.query(
        `UPDATE webhook_deliveries SET status = 'failed' WHERE id = $1`,
        [delivery.id]
      );
      continue;
    }

    await deliverWebhook(delivery.webhook_config_id, delivery.event_type, payload);
  }
}

// ============================================
// WEBHOOK CONFIGURATION MANAGEMENT
// ============================================

export async function createWebhookConfig(
  name: string,
  endpointUrl: string,
  eventTypes: string[],
  createdBy: string,
  options?: {
    description?: string;
    secret?: string;
    retryCount?: number;
    retryDelaySeconds?: number;
    timeoutSeconds?: number;
  }
): Promise<string> {
  const result = await client.query(
    `INSERT INTO webhook_configs 
     (name, description, endpoint_url, secret, event_types, retry_count, retry_delay_seconds, timeout_seconds, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id`,
    [
      name,
      options?.description || null,
      endpointUrl,
      options?.secret || null,
      eventTypes,
      options?.retryCount || 3,
      options?.retryDelaySeconds || 60,
      options?.timeoutSeconds || 30,
      createdBy,
    ]
  );

  return result.rows[0].id;
}

export async function listWebhookConfigs(): Promise<WebhookConfig[]> {
  const result = await client.query(
    'SELECT * FROM webhook_configs ORDER BY created_at DESC'
  );
  return result.rows;
}

export async function getWebhookConfig(id: string): Promise<WebhookConfig | null> {
  const result = await client.query(
    'SELECT * FROM webhook_configs WHERE id = $1',
    [id]
  );
  return result.rows[0] || null;
}

export async function updateWebhookConfig(
  id: string,
  updates: Partial<{
    name: string;
    description: string;
    endpoint_url: string;
    event_types: string[];
    is_active: boolean;
    retry_count: number;
    retry_delay_seconds: number;
    timeout_seconds: number;
  }>
): Promise<boolean> {
  const setClauses: string[] = [];
  const values: any[] = [];
  let paramIndex = 1;

  Object.entries(updates).forEach(([key, value]) => {
    setClauses.push(`${key} = $${paramIndex++}`);
    values.push(value);
  });

  if (setClauses.length === 0) return false;

  setClauses.push(`updated_at = NOW()`);
  values.push(id);

  const result = await client.query(
    `UPDATE webhook_configs SET ${setClauses.join(', ')} WHERE id = $${paramIndex}`,
    values
  );

  return result.rowCount !== null;
}

export async function deleteWebhookConfig(id: string): Promise<boolean> {
  const result = await client.query(
    'DELETE FROM webhook_configs WHERE id = $1',
    [id]
  );
  return result.rowCount !== null;
}

// ============================================
// GITHUB APP INSTALLATION
// ============================================

export async function recordGitHubInstallation(
  installationId: string,
  accountId: string,
  accountName: string,
  permissions: Record<string, any>,
  events: string[]
): Promise<string> {
  const result = await client.query(
    `INSERT INTO webhook_installations 
     (provider, installation_id, account_id, account_name, permissions, events)
     VALUES ('github', $1, $2, $3, $4, $5)
     ON CONFLICT (provider, installation_id) 
     DO UPDATE SET account_name = $3, permissions = $4, events = $5, is_active = TRUE
     RETURNING id`,
    [installationId, accountId, accountName, JSON.stringify(permissions), events]
  );

  return result.rows[0].id;
}

export async function linkRepository(
  installationId: string,
  repoId: string,
  repoName: string,
  repoFullName: string,
  defaultBranch: string = 'main'
): Promise<string> {
  const result = await client.query(
    `INSERT INTO webhook_repo_links 
     (installation_id, repo_id, repo_name, repo_full_name, default_branch)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (installation_id, repo_id) 
     DO UPDATE SET repo_name = $3, repo_full_name = $4, default_branch = $5, is_active = TRUE
     RETURNING id`,
    [installationId, repoId, repoName, repoFullName, defaultBranch]
  );

  return result.rows[0].id;
}

export async function getInstallationRepos(installationId: string) {
  const result = await client.query(
    `SELECT * FROM webhook_repo_links 
     WHERE installation_id = $1 AND is_active = TRUE
     ORDER BY repo_name`,
    [installationId]
  );
  return result.rows;
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

export function verifyGitHubSignature(payload: string, signature: string | undefined, secret: string): boolean {
  if (!signature) return false;

  const expectedSignature = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

export async function getPendingDeliveries(limit: number = 100) {
  const result = await client.query(
    `SELECT * FROM webhook_deliveries 
     WHERE status IN ('pending', 'retrying')
     ORDER BY created_at DESC
     LIMIT $1`,
    [limit]
  );
  return result.rows;
}

export async function getDeliveryStats() {
  const result = await client.query(`
    SELECT 
      status,
      COUNT(*) as count,
      AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) as avg_duration_seconds
    FROM webhook_deliveries
    WHERE created_at >= NOW() - INTERVAL '24 hours'
    GROUP BY status
  `);

  return result.rows;
}
