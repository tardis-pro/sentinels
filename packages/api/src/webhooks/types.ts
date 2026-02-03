import crypto from 'crypto';

export type GitProvider = 'github' | 'gitlab' | 'bitbucket';

export interface WebhookConfig {
  id: string;
  projectId: string;
  provider: GitProvider;
  events: string[];
  url: string;
  secret: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: string;
  payload: any;
  status: 'pending' | 'success' | 'failed';
  responseCode?: number;
  responseBody?: string;
  attempts: number;
  createdAt: string;
  deliveredAt?: string;
}

export interface ScanTrigger {
  id: string;
  projectId: string;
  triggerType: 'push' | 'pr_open' | 'pr_update' | 'pr_merge' | 'schedule' | 'manual' | 'webhook';
  source: string;
  branch?: string;
  commitSha?: string;
  prNumber?: number;
  config: {
    scanners: string[];
    diffMode: boolean;
    autoScan: boolean;
    failOnCritical: boolean;
  };
  status: 'pending' | 'running' | 'completed' | 'failed';
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
}

export interface GitProviderConfig {
  provider: GitProvider;
  apiUrl: string;
  token: string;
  webhookSecret?: string;
}

export interface CommitStatus {
  sha: string;
  state: 'pending' | 'success' | 'failure' | 'error';
  description: string;
  targetUrl?: string;
  context: string;
}

export interface PRComment {
  prNumber: number;
  body: string;
  commitSha: string;
}
