// Auto-Remediation PR Generation - Issue #8
export interface FixConfig { autoCreatePR: boolean; requireApproval: boolean; }
export async function generateFix(findingId: string): Promise<{ diff: string; prTitle: string }> {
  void findingId;
  return { diff: '--- a/file.js\n+++ b/file.js', prTitle: 'Fix security vulnerability' };
}
