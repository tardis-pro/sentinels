import crypto from 'crypto';
import { GitProviderClient, CommitStatus, PRComment } from '../index';
import { GitProviderConfig } from '../types';

export class GitHubClient implements GitProviderClient {
  provider = 'github' as const;
  private config: GitProviderConfig;
  private baseUrl = 'https://api.github.com';

  constructor(config: GitProviderConfig) {
    this.config = config;
    if (config.apiUrl) {
      this.baseUrl = config.apiUrl;
    }
  }

  async setCommitStatus(status: CommitStatus): Promise<void> {
    const [owner, repo] = this.getOwnerRepo();
    const response = await fetch(
      `${this.baseUrl}/repos/${owner}/${repo}/statuses/${status.sha}`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          Accept: 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          state: status.state,
          description: status.description,
          target_url: status.targetUrl,
          context: status.context,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to set commit status: ${response.statusText}`);
    }
  }

  async createPRComment(comment: PRComment): Promise<void> {
    const [owner, repo] = this.getOwnerRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repos/${owner}/${repo}/issues/${comment.prNumber}/comments`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          Accept: 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: comment.body,
          commit_id: comment.commitSha,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to create PR comment: ${response.statusText}`);
    }
  }

  async updatePRComment(prNumber: number, commentId: string, body: string): Promise<void> {
    const [owner, repo] = this.getOwnerRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repos/${owner}/${repo}/issues/comments/${commentId}`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          Accept: 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ body }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to update PR comment: ${response.statusText}`);
    }
  }

  verifySignature(payload: string, signature: string, secret: string): boolean {
    const expectedSignature = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  }

  parsePushEvent(payload: any): { 
    repository: string; 
    branch: string; 
    commitSha: string; 
    changes: { added?: string[]; modified?: string[]; removed?: string[] } 
  } {
    const repo = payload.repository?.full_name || payload.repository?.name;
    const branch = payload.ref?.replace('refs/heads/', '');
    const commitSha = payload.after || payload.head_commit?.id;
    
    const changes = {
      added: payload.head_commit?.added || [],
      modified: payload.head_commit?.modified || [],
      removed: payload.head_commit?.removed || [],
    };

    return { repository: repo, branch, commitSha, changes };
  }

  parsePREvent(payload: any): {
    action: 'opened' | 'synchronize' | 'closed' | 'reopened';
    prNumber: number;
    title: string;
    branch: string;
    baseBranch: string;
    author: string;
  } {
    const pr = payload.pull_request;
    return {
      action: payload.action,
      prNumber: pr.number,
      title: pr.title,
      branch: pr.head?.ref,
      baseBranch: pr.base?.ref,
      author: pr.user?.login,
    };
  }

  async getFileContent(repo: string, path: string, ref: string): Promise<string> {
    const response = await fetch(
      `${this.baseUrl}/repos/${repo}/contents/${path}?ref=${ref}`,
      {
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          Accept: 'application/vnd.github.v3.raw',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get file: ${response.statusText}`);
    }

    return response.text();
  }

  async getCommit(repo: string, sha: string): Promise<any> {
    const response = await fetch(
      `${this.baseUrl}/repos/${repo}/commits/${sha}`,
      {
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          Accept: 'application/vnd.github.v3+json',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get commit: ${response.statusText}`);
    }

    return response.json();
  }

  private getOwnerRepo(): [string, string] {
    // Owner and repo should come from config, not derived from token
    // The config should have owner and repo fields for proper operation
    if (this.config.owner && this.config.repo) {
      return [this.config.owner, this.config.repo];
    }
    // Fallback: try to extract from repository info in config
    // This is a workaround for existing configurations
    throw new Error('GitHub owner and repo must be configured');
  }
}
