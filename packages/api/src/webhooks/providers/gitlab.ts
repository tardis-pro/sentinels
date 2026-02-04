import crypto from 'crypto';
import { GitProviderClient, CommitStatus, PRComment } from '../index';
import { GitProviderConfig } from '../types';

export class GitLabClient implements GitProviderClient {
  provider = 'gitlab' as const;
  private config: GitProviderConfig;
  private baseUrl: string;

  constructor(config: GitProviderConfig) {
    this.config = config;
    this.baseUrl = config.apiUrl || 'https://gitlab.com/api/v4';
  }

  async setCommitStatus(status: CommitStatus): Promise<void> {
    const [projectPath, sha] = this.parseRef(status.context);
    
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(projectPath)}/statuses/${sha}`,
      {
        method: 'POST',
        headers: {
          'PRIVATE-TOKEN': this.config.token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          state: this.mapStatus(status.state),
          description: status.description,
          target_url: status.targetUrl,
          name: status.context,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to set commit status: ${response.statusText}`);
    }
  }

  async createPRComment(comment: PRComment): Promise<void> {
    const [projectPath] = this.parseRef(comment.commitSha);
    
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(projectPath)}/merge_requests/${comment.prNumber}/notes`,
      {
        method: 'POST',
        headers: {
          'PRIVATE-TOKEN': this.config.token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: comment.body,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to create MR comment: ${response.statusText}`);
    }
  }

  async updatePRComment(prNumber: number, commentId: string, body: string): Promise<void> {
    // Get project path from config - required for GitLab operations
    const projectPath = this.getProjectPath();
    
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(projectPath)}/merge_requests/${prNumber}/notes/${commentId}`,
      {
        method: 'PUT',
        headers: {
          'PRIVATE-TOKEN': this.config.token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ body }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to update MR comment: ${response.statusText}`);
    }
  }

  verifySignature(payload: string, signature: string, secret: string): boolean {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  }

  parsePushEvent(payload: any): { 
    repository: string; 
    branch: string; 
    commitSha: string; 
    changes: { added?: string[]; modified?: string[]; removed?: string[] } 
  } {
    const repo = payload.project?.path_with_namespace;
    const branch = payload.ref?.replace('refs/heads/', '');
    const commitSha = payload.after;
    
    // Extract changed files from commits array
    const changes = {
      added: [] as string[],
      modified: [] as string[],
      removed: [] as string[],
    };
    
    if (payload.commits && Array.isArray(payload.commits)) {
      for (const commit of payload.commits) {
        if (commit.added) changes.added.push(...commit.added);
        if (commit.modified) changes.modified.push(...commit.modified);
        if (commit.removed) changes.removed.push(...commit.removed);
      }
    }

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
    const mr = payload.object_attributes;
    return {
      action: mr.action,
      prNumber: mr.iid,
      title: mr.title,
      branch: mr.source_branch,
      baseBranch: mr.target_branch,
      author: mr.author?.username,
    };
  }

  async getFileContent(repo: string, path: string, ref: string): Promise<string> {
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(repo)}/repository/files/${encodeURIComponent(path)}?ref=${ref}`,
      {
        headers: {
          'PRIVATE-TOKEN': this.config.token,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get file: ${response.statusText}`);
    }

    const data = await response.json();
    return Buffer.from(data.content, 'base64').toString('utf8');
  }

  async getCommit(repo: string, sha: string): Promise<any> {
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(repo)}/commits/${sha}`,
      {
        headers: {
          'PRIVATE-TOKEN': this.config.token,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get commit: ${response.statusText}`);
    }

    return response.json();
  }

  private parseRef(ref: string): [string, string] {
    // Extract project path and commit SHA from ref or context
    // For commits: use the SHA directly
    if (ref && ref.length >= 7 && !ref.includes('/')) {
      const projectPath = this.getProjectPath();
      return [projectPath, ref];
    }
    // For refs: project_path@sha
    const parts = ref.split('@');
    return [parts[0], parts[1] || ''];
  }

  private getProjectPath(): string {
    // Project path should come from config
    if (this.config.projectPath) {
      return this.config.projectPath;
    }
    throw new Error('GitLab project path must be configured');
  }

  private mapStatus(state: string): string {
    const statusMap: Record<string, string> = {
      pending: 'pending',
      success: 'success',
      failure: 'failed',
      error: 'failed',
    };
    return statusMap[state] || 'pending';
  }
}
    };
  }

  async getFileContent(repo: string, path: string, ref: string): Promise<string> {
    const response = await fetch(
      `${this.baseUrl}/projects/${encodeURIComponent(repo)}/repository/files/${encodeURIComponent(path)}/raw?ref=${ref}`,
      {
        headers: {
          'PRIVATE-TOKEN': this.config.token,
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
      `${this.baseUrl}/projects/${encodeURIComponent(repo)}/commits/${sha}`,
      {
        headers: {
          'PRIVATE-TOKEN': this.config.token,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get commit: ${response.statusText}`);
    }

    return response.json();
  }

  private parseRef(ref: string): [string, string] {
    const parts = ref.split('/');
    const sha = parts.pop();
    const projectPath = parts.join('/');
    return [projectPath, sha];
  }

  private mapStatus(status: string): string {
    const map: Record<string, string> = {
      pending: 'pending',
      success: 'success',
      failure: 'failed',
      error: 'failed',
    };
    return map[status] || 'pending';
  }
}
