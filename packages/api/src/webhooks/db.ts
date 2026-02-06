import crypto from 'crypto';
import { client, connectDb } from '../db';
import { WebhookConfig, WebhookDelivery, ScanTrigger, GitProviderConfig } from './types';
import { createGitProviderClient } from './index';

// Simple encryption for secrets
const ENCRYPTION_KEY = process.env.SENTINEL_ENCRYPTION_KEY || 'default-key-32-bytes-long!!';
const IV_LENGTH = 16;

export function encryptSecret(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY.padEnd(32)), iv);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex');
}

export function decryptSecret(text: string): string {
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

// Database tables for webhook functionality
export async function createWebhookTables(): Promise<void> {
  await connectDb();

  await client.query(`
    -- Webhook configurations (compatible with service.ts and db.ts)
    CREATE TABLE IF NOT EXISTS webhook_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      provider VARCHAR(20) NOT NULL,
      events TEXT[] NOT NULL DEFAULT '{}',
      url TEXT NOT NULL,
      secret TEXT NOT NULL,
      enabled BOOLEAN DEFAULT true,
      name TEXT,
      description TEXT,
      endpoint_url TEXT,
      event_types TEXT[] DEFAULT '{}',
      is_active BOOLEAN DEFAULT true,
      retry_count INT DEFAULT 3,
      retry_delay_seconds INT DEFAULT 60,
      timeout_seconds INT DEFAULT 30,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_webhook_configs_project ON webhook_configs(project_id);

    -- Webhook delivery history (compatible with service.ts and db.ts)
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      webhook_id UUID REFERENCES webhook_configs(id) ON DELETE CASCADE,
      webhook_config_id UUID REFERENCES webhook_configs(id) ON DELETE CASCADE,
      event TEXT NOT NULL,
      event_type TEXT,
      payload JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      response_code INT,
      response_status INT,
      response_headers JSONB,
      response_body TEXT,
      attempts INT DEFAULT 0,
      error_message TEXT,
      next_retry_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      delivered_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_config ON webhook_deliveries(webhook_config_id);
    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);

    -- Scan triggers
    CREATE TABLE IF NOT EXISTS scan_triggers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      trigger_type VARCHAR(20) NOT NULL,
      source TEXT NOT NULL,
      branch TEXT,
      commit_sha TEXT,
      pr_number INT,
      config JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_scan_triggers_project ON scan_triggers(project_id);
    CREATE INDEX IF NOT EXISTS idx_scan_triggers_status ON scan_triggers(status);

    -- Git provider configurations
    CREATE TABLE IF NOT EXISTS git_provider_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      provider VARCHAR(20) NOT NULL,
      api_url TEXT,
      token_encrypted TEXT NOT NULL,
      webhook_secret TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_git_provider_configs_project ON git_provider_configs(project_id);

    DO $$ BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_git_provider_configs_project_provider'
      ) THEN
        ALTER TABLE git_provider_configs
        ADD CONSTRAINT uq_git_provider_configs_project_provider UNIQUE (project_id, provider);
      END IF;
    END $$;

    ALTER TABLE webhook_configs ALTER COLUMN provider DROP NOT NULL;
    ALTER TABLE webhook_configs ALTER COLUMN events DROP NOT NULL;
    ALTER TABLE webhook_configs ALTER COLUMN url DROP NOT NULL;
    ALTER TABLE webhook_configs ALTER COLUMN secret DROP NOT NULL;

    ALTER TABLE webhook_deliveries ALTER COLUMN webhook_id DROP NOT NULL;
    ALTER TABLE webhook_deliveries ALTER COLUMN event DROP NOT NULL;
  `);

  console.log('Webhook tables created successfully');
}

// Webhook CRUD operations
export async function createWebhookConfig(params: {
  projectId: string;
  provider: string;
  events: string[];
  url: string;
  secret: string;
}): Promise<WebhookConfig> {
  const result = await client.query<WebhookConfig>(
    `INSERT INTO webhook_configs (project_id, provider, events, url, secret)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [params.projectId, params.provider, params.events, params.url, params.secret]
  );
  return result.rows[0];
}

export async function getWebhookConfigs(projectId: string): Promise<WebhookConfig[]> {
  const result = await client.query<WebhookConfig>(
    'SELECT * FROM webhook_configs WHERE project_id = $1 ORDER BY created_at DESC',
    [projectId]
  );
  return result.rows;
}

export async function updateWebhookConfig(
  id: string,
  updates: Partial<WebhookConfig>
): Promise<WebhookConfig | null> {
  const setClauses: string[] = [];
  const values: any[] = [];
  let paramIndex = 1;

  if (updates.events) {
    setClauses.push(`events = $${paramIndex++}`);
    values.push(updates.events);
  }
  if (updates.url) {
    setClauses.push(`url = $${paramIndex++}`);
    values.push(updates.url);
  }
  if (updates.enabled !== undefined) {
    setClauses.push(`enabled = $${paramIndex++}`);
    values.push(updates.enabled);
  }
  if (updates.secret) {
    setClauses.push(`secret = $${paramIndex++}`);
    values.push(updates.secret);
  }

  setClauses.push(`updated_at = NOW()`);
  values.push(id);

  const result = await client.query<WebhookConfig>(
    `UPDATE webhook_configs SET ${setClauses.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
    values
  );
  return result.rows[0] || null;
}

export async function deleteWebhookConfig(id: string): Promise<void> {
  await client.query('DELETE FROM webhook_configs WHERE id = $1', [id]);
}

// Scan trigger operations
export async function createScanTrigger(params: {
  projectId: string;
  triggerType: string;
  source: string;
  branch?: string;
  commitSha?: string;
  prNumber?: number;
  config: any;
}): Promise<ScanTrigger> {
  const result = await client.query<ScanTrigger>(
    `INSERT INTO scan_triggers 
      (project_id, trigger_type, source, branch, commit_sha, pr_number, config, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
     RETURNING *`,
    [
      params.projectId,
      params.triggerType,
      params.source,
      params.branch,
      params.commitSha,
      params.prNumber,
      JSON.stringify(params.config),
    ]
  );
  return result.rows[0];
}

export async function getPendingTriggers(projectId?: string): Promise<ScanTrigger[]> {
  let query = 'SELECT * FROM scan_triggers WHERE status = $1';
  const params: any[] = ['pending'];

  if (projectId) {
    query += ' AND project_id = $2';
    params.push(projectId);
  }

  query += ' ORDER BY created_at ASC';

  const result = await client.query<ScanTrigger>(query, params);
  return result.rows;
}

export async function updateScanTriggerStatus(
  id: string,
  status: string,
  startedAt?: Date,
  completedAt?: Date
): Promise<void> {
  const updates: string[] = ['status = $2'];
  const values: any[] = [id, status];
  let paramIndex = 3;

  if (startedAt) {
    updates.push(`started_at = $${paramIndex++}`);
    values.push(startedAt);
  }
  if (completedAt) {
    updates.push(`completed_at = $${paramIndex++}`);
    values.push(completedAt);
  }

  await client.query(
    `UPDATE scan_triggers SET ${updates.join(', ')} WHERE id = $1`,
    values
  );
}

// Webhook delivery logging
export async function logWebhookDelivery(params: {
  webhookId: string;
  event: string;
  payload: any;
  status: string;
  responseCode?: number;
  responseBody?: string;
}): Promise<void> {
  // Use a unique constraint on (webhook_id, event, created_at) for deduplication
  await client.query(
    `INSERT INTO webhook_deliveries 
      (webhook_id, event, payload, status, response_code, response_body, attempts)
     VALUES ($1, $2, $3, $4, $5, $6, 1)
     ON CONFLICT DO NOTHING`,
    [
      params.webhookId,
      params.event,
      JSON.stringify(params.payload),
      params.status,
      params.responseCode,
      params.responseBody,
    ]
  );
}

// Git provider config operations
export async function saveGitProviderConfig(params: {
  projectId: string;
  provider: string;
  apiUrl?: string;
  token: string;
  webhookSecret?: string;
}): Promise<void> {
  // Encrypt sensitive data before storage
  const encryptedToken = encryptSecret(params.token);
  const encryptedWebhookSecret = params.webhookSecret ? encryptSecret(params.webhookSecret) : null;
  
  await client.query(
    `INSERT INTO git_provider_configs (project_id, provider, api_url, token_encrypted, webhook_secret)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (project_id, provider) DO UPDATE SET
      api_url = EXCLUDED.api_url,
      token_encrypted = EXCLUDED.token_encrypted,
      webhook_secret = EXCLUDED.webhook_secret,
      updated_at = NOW()`,
    [params.projectId, params.provider, params.apiUrl, encryptedToken, encryptedWebhookSecret]
  );
}

export async function getGitProviderConfig(projectId: string): Promise<any | null> {
  const result = await client.query(
    'SELECT * FROM git_provider_configs WHERE project_id = $1',
    [projectId]
  );
  return result.rows[0] || null;
}
