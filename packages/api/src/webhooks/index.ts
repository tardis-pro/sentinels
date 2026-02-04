import { GitProvider, GitProviderConfig, CommitStatus, PRComment } from './types';

export interface GitProviderClient {
  provider: GitProvider;
  
  // Commit status
  setCommitStatus(status: CommitStatus): Promise<void>;
  
  // PR comments
  createPRComment(comment: PRComment): Promise<void>;
  updatePRComment(prNumber: number, commentId: string, body: string): Promise<void>;
  
  // Webhook verification
  verifySignature(payload: string, signature: string, secret: string): boolean;
  
  // Parse webhook events
  parsePushEvent(payload: any): { 
    repository: string; 
    branch: string; 
    commitSha: string; 
    changes: { added?: string[]; modified?: string[]; removed?: string[] } 
  };
  
  parsePREvent(payload: any): {
    action: 'opened' | 'synchronize' | 'closed' | 'reopened';
    prNumber: number;
    title: string;
    branch: string;
    baseBranch: string;
    author: string;
  };
  
  // API access
  getFileContent(repo: string, path: string, ref: string): Promise<string>;
  getCommit(repo: string, sha: string): Promise<any>;
}

export { GitHubClient } from './providers/github';
export { GitLabClient } from './providers/gitlab';
export { BitbucketClient } from './providers/bitbucket';

export function createGitProviderClient(config: GitProviderConfig): GitProviderClient {
  switch (config.provider) {
    case 'github':
      return new GitHubClient(config);
    case 'gitlab':
      return new GitLabClient(config);
    case 'bitbucket':
      return new BitbucketClient(config);
    default:
      throw new Error(`Unsupported git provider: ${config.provider}`);
  }
}

// Webhook routes for receiving webhooks from Git providers
export { webhookRoutes } from './routes';
export * from './service';
