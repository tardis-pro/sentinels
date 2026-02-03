// Team Collaboration & Triage Workflow Feature - Issue #6
// Finding assignment, workflow management, commenting, threaded discussions, integration with issue tracking systems
export interface FindingState {
  id: string;
  status: 'open' | 'assigned' | 'in_progress' | 'under_review' | 'remediated' | 'closed' | 'false_positive' | 'risk_accepted';
  assignee?: string;
  comments: Comment[];
}
export interface Comment {
  id: string;
  author: string;
  content: string;
  createdAt: string;
}
export { createCollaborationService } from './service';
