import crypto from 'crypto';
import { GitProviderClient, CommitStatus, PRComment } from '../index';
import { GitProviderConfig } from '../types';

export class BitbucketClient implements GitProviderClient {
  provider = 'bitbucket' as const;
  private config: GitProviderConfig;
  private baseUrl = 'https://api.bitbucket.org/2.0';

  constructor(config: GitProviderConfig) {
    this.config = config;
    if (config.apiUrl) {
      this.baseUrl = config.apiUrl;
    }
  }

  async setCommitStatus(status: CommitStatus): Promise<void> {
    const [workspace, repo] = this.getWorkspaceRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repositories/${workspace}/${repo}/commit/${status.sha}/statuses/build`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          state: this.mapStatus(status.state),
          description: status.description,
          url: status.targetUrl,
          key: status.context,
          name: status.context,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to set commit status: ${response.statusText}`);
    }
  }

  async createPRComment(comment: PRComment): Promise<void> {
    const [workspace, repo] = this.getWorkspaceRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repositories/${workspace}/${repo}/pullrequests/${comment.prNumber}/comments`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content: { raw: comment.body },
          commit: comment.commitSha,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to create PR comment: ${response.statusText}`);
    }
  }

  async updatePRComment(prNumber: number, commentId: string, body: string): Promise<void> {
    const [workspace, repo] = this.getWorkspaceRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repositories/${workspace}/${repo}/pullrequests/${prNumber}/comments/${commentId}`,
      {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content: { raw: body },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to update PR comment: ${response.statusText}`);
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
    const repo = payload.repository?.full_name;
    const branch = payload.push?.changes?.[0]?.new?.name;
    const commitSha = payload.push?.changes?.[0]?.new?.target?.hash;
    
    // Extract changed files from commits
    const changes = {
      added: [] as string[],
      modified: [] as string[],
      removed: [] as string[],
    };
    
    const changesObj = payload.push?.changes?.[0];
    if (changesObj?.commits && Array.isArray(changesObj.commits)) {
      for (const commit of changesObj.commits) {
        if (commit.added) changes.added.push(...commit.added);
        if (commit.modified) changes.modified.push(...commit.modified);
        if (commit.removed) changes.removed.push(...commit.removed);
      }
    }
    
    return { 
      repository: repo, 
      branch, 
      commitSha, 
      changes
    };
  }

  parsePREvent(payload: any): {
    action: 'opened' | 'synchronize' | 'closed' | 'reopened';
    prNumber: number;
    title: string;
    branch: string;
    baseBranch: string;
    author: string;
  } {
    const pr = payload.pullrequest;
    const action = this.mapPREventAction(payload.action, pr.state);
    return {
      action,
      prNumber: pr.id,
      title: pr.title,
      branch: pr.source?.branch?.name,
      baseBranch: pr.destination?.branch?.name,
      author: pr.author?.display_name,
    };
  }

  private mapPREventAction(action: string, state: string): 'opened' | 'synchronize' | 'closed' | 'reopened' {
    // Map Bitbucket actions to our action types
    const actionMap: Record<string, 'opened' | 'synchronize' | 'closed' | 'reopened'> = {
      'created': 'opened',
      'updated': 'synchronize',
      'opened': 'opened',
      'closed': 'closed',
      'reopened': 'reopened',
      'merge': 'closed',
    };
    return actionMap[action] || 'opened';
  }

  async getFileContent(repo: string, path: string, ref: string): Promise<string> {
    const [workspace, repoName] = this.getWorkspaceRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repositories/${workspace}/${repoName}/src/${ref}/${path}`,
      {
        headers: {
          Authorization: `Bearer ${this.config.token}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get file: ${response.statusText}`);
    }

    return response.text();
  }

  async getCommit(repo: string, sha: string): Promise<any> {
    const [workspace, repoName] = this.getWorkspaceRepo();
    
    const response = await fetch(
      `${this.baseUrl}/repositories/${workspace}/${repoName}/commit/${sha}`,
      {
        headers: {
          Authorization: `Bearer ${this.config.token}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get commit: ${response.statusText}`);
    }

    return response.json();
  }

  private getWorkspaceRepo(): [string, string] {
    // Workspace and repo should come from config, not derived from token
    if (this.config.workspace && this.config.repo) {
      return [this.config.workspace, this.config.repo];
    }
    throw new Error('Bitbucket workspace and repo must be configured');
  }

  private mapStatus(status: string): string {
    const map: Record<string, string> = {
      pending: 'INPROGRESS',
      success: 'SUCCESSFUL',
      failure: 'FAILED',
      error: 'FAILED',
    };
    return map[status] || 'INPROGRESS';
  }
}
