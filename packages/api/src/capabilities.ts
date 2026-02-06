import { hasIgnorePatterns, toHostPath } from './config';
import { streamScanEvents } from './events';
import {
  saveAIAnalysis,
  getAIAnalysis,
  saveFindingEmbedding,
  createChatSession,
  addChatMessage,
  getChatSession,
  saveAIFeedback,
} from './ai/db';
import { isAIServiceAvailable, resetAIProvider, createProvider } from './ai';
import {
  connectAnalyticsDb,
  getAnalyticsSummary,
  getFindingTrends,
  getProjectScores,
  getScannerPerformance,
  getComplianceSummary,
  refreshMaterializedViews,
  trackAnalyticsEvent,
  getSecurityPostureHistory,
  getFindingDensityByType,
  getRemediationVelocity,
} from './analytics';
import {
  getUserByEmail,
  getOrganization,
  getAssignedFindings,
  checkSLABreachesForFinding,
  getFindingRiskAcceptance,
} from './collaboration';
import { collaborationRoutes } from './collaboration/routes';
import { findDuplicates } from './deduplication';
import { generateFix } from './fixes';
import { createPluginRegistry, createPluginSandbox } from './plugins/registry';
import {
  connectPolicyDb,
  createPolicy,
  getPolicyById,
  listPolicies,
  updatePolicy,
  deletePolicy,
  evaluatePolicyWithOPA,
  evaluateFindingAgainstPolicies,
  evaluateProjectCompliance,
  seedBuiltInPolicies,
  createComplianceFramework,
  getComplianceFrameworks,
  getPolicyStatistics,
  builtInPolicies,
} from './policies';
import { generateSBOM } from './sbom';
import { createSchedule } from './scheduler';
import {
  decryptSecret,
  createWebhookTables,
  createWebhookConfig as createWebhookConfigDb,
  getWebhookConfigs,
  updateWebhookConfig as updateWebhookConfigDb,
  deleteWebhookConfig as deleteWebhookConfigDb,
  logWebhookDelivery,
} from './webhooks/db';
import {
  connectWebhooksDb,
  processGitHubWebhook,
  deliverWebhook,
  retryFailedDeliveries,
  createWebhookConfig,
  listWebhookConfigs,
  getWebhookConfig,
  updateWebhookConfig,
  deleteWebhookConfig,
  recordGitHubInstallation,
  linkRepository,
  getInstallationRepos,
  verifyGitHubSignature,
  getPendingDeliveries,
  getDeliveryStats,
} from './webhooks';
import type { FixConfig } from './fixes';
import type { EnrichmentPlugin, NotificationPlugin, ReportPlugin, PluginLifecycle } from './plugins/types';
import type { Dependency } from './sbom';
import type { ScheduleConfig } from './scheduler';

export type UnusedApiTypeSurface = {
  fix: FixConfig;
  plugin: EnrichmentPlugin | NotificationPlugin | ReportPlugin | PluginLifecycle;
  dependency: Dependency;
  schedule: ScheduleConfig;
};

const typeSurfaceCheck: UnusedApiTypeSurface | null = null;
void typeSurfaceCheck;

export function buildCapabilityManifest() {
  return {
    config: { hasIgnorePatterns, toHostPath },
    events: { streamScanEvents },
    aiDb: {
      saveAIAnalysis,
      getAIAnalysis,
      saveFindingEmbedding,
      createChatSession,
      addChatMessage,
      getChatSession,
      saveAIFeedback,
    },
    aiProviders: { isAIServiceAvailable, resetAIProvider, createProvider },
    analytics: {
      connectAnalyticsDb,
      getAnalyticsSummary,
      getFindingTrends,
      getProjectScores,
      getScannerPerformance,
      getComplianceSummary,
      refreshMaterializedViews,
      trackAnalyticsEvent,
      getSecurityPostureHistory,
      getFindingDensityByType,
      getRemediationVelocity,
    },
    collaboration: {
      collaborationRoutes,
      getUserByEmail,
      getOrganization,
      getAssignedFindings,
      checkSLABreachesForFinding,
      getFindingRiskAcceptance,
    },
    deduplication: { findDuplicates },
    fixes: { generateFix },
    plugins: { createPluginRegistry, createPluginSandbox },
    policies: {
      connectPolicyDb,
      createPolicy,
      getPolicyById,
      listPolicies,
      updatePolicy,
      deletePolicy,
      evaluatePolicyWithOPA,
      evaluateFindingAgainstPolicies,
      evaluateProjectCompliance,
      seedBuiltInPolicies,
      createComplianceFramework,
      getComplianceFrameworks,
      getPolicyStatistics,
      builtInPolicies,
    },
    sbom: { generateSBOM },
    scheduler: { createSchedule },
    webhookDb: {
      decryptSecret,
      createWebhookTables,
      createWebhookConfigDb,
      getWebhookConfigs,
      updateWebhookConfigDb,
      deleteWebhookConfigDb,
      logWebhookDelivery,
    },
    webhooks: {
      connectWebhooksDb,
      processGitHubWebhook,
      deliverWebhook,
      retryFailedDeliveries,
      createWebhookConfig,
      listWebhookConfigs,
      getWebhookConfig,
      updateWebhookConfig,
      deleteWebhookConfig,
      recordGitHubInstallation,
      linkRepository,
      getInstallationRepos,
      verifyGitHubSignature,
      getPendingDeliveries,
      getDeliveryStats,
    },
  };
}
