// Scan Scheduling & Monitoring - Issue #10
export interface ScheduleConfig { cronExpression: string; timezone: string; enabled: boolean; }
export async function createSchedule(projectId: string, config: ScheduleConfig): Promise<string> {
  return 'schedule-id';
}
