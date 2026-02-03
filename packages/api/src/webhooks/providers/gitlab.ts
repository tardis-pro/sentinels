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
    const [projectPath, ] = this.parseRef(comment.commitSha);
    
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
    const [projectPath, ] = this.parseRef('');
    
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
    
    const changes = {
      added: payload.project?.default_branch === branch ? [] : [],
      modified: [],
      removed: [],
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
