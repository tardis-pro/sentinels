import crypto from 'crypto';
import { getAIProvider, AIProviderClient } from './index';
import { 
  AIAnalysisConfig, 
  AIAnalysisResult, 
  FindingContext, 
  FindingEmbedding,
  SimilarFinding,
  getDefaultConfig 
} from './types';
import { client as pgClient } from '../db';

/**
 * AI Analysis Service
 * Core service for analyzing security findings using AI
 */
export class AIAnalysisService {
  private provider!: AIProviderClient;
  private config: AIAnalysisConfig;
  private cache: Map<string, { result: AIAnalysisResult; timestamp: number }>;
  private cacheTTL: number;
  private initialized: boolean = false;

  constructor(provider?: AIProviderClient, config?: AIAnalysisConfig) {
    this.config = config || getDefaultConfig();
    this.cache = new Map();
    this.cacheTTL = 24 * 60 * 60 * 1000;
  }

  private async ensureProvider(): Promise<void> {
    if (!this.initialized) {
      this.provider = await getAIProvider(this.config);
      this.initialized = true;
    }
  }

  /**
   * Analyze a security finding
   */
  async analyzeFinding(finding: FindingContext): Promise<AIAnalysisResult> {
    await this.ensureProvider();
    const startTime = Date.now();
    const fingerprint = this.generateFingerprint(finding);

    // Check cache first
    const cached = this.cache.get(fingerprint);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      console.log(`Cache hit for finding ${finding.ruleId}`);
      return cached.result;
    }

    try {
      // Generate analysis
      const [analysis, remediation] = await Promise.all([
        this.provider.analyzeFinding(finding),
        this.provider.generateRemediation(finding),
      ]);

      const analysisResult = this.parseAnalysis(analysis);
      const remediationResult = this.parseRemediation(remediation);

      // Calculate prioritization
      const prioritization = this.calculatePrioritization(finding, analysisResult);

      const result: AIAnalysisResult = {
        id: crypto.randomUUID(),
        findingId: finding.ruleId,
        analysis: analysisResult,
        suggestions: remediationResult,
        prioritization,
        metadata: {
          model: this.config.model,
          provider: this.config.provider,
          tokensUsed: await this.provider.countTokens(analysis + remediation),
          processingTimeMs: Date.now() - startTime,
          timestamp: new Date().toISOString(),
        },
      };

      // Cache the result
      this.cache.set(fingerprint, { result, timestamp: Date.now() });

      // Store in database
      await this.storeAnalysis(fingerprint, finding, result);

      return result;
    } catch (error) {
      console.error(`AI analysis failed for ${finding.ruleId}:`, error);
      throw error;
    }
  }

  /**
   * Analyze multiple findings in batch
   */
  async analyzeFindings(findings: FindingContext[]): Promise<Map<string, AIAnalysisResult>> {
    await this.ensureProvider();
    const results = new Map<string, AIAnalysisResult>();

    // Process in parallel with concurrency limit
    const concurrency = 5;
    for (let i = 0; i < findings.length; i += concurrency) {
      const batch = findings.slice(i, i + concurrency);
      const batchResults = await Promise.allSettled(
        batch.map(f => this.analyzeFinding(f))
      );

      batch.forEach((finding, idx) => {
        const result = batchResults[idx];
        if (result.status === 'fulfilled') {
          results.set(finding.ruleId, result.value);
        } else {
          console.error(`Batch analysis failed for ${finding.ruleId}:`, result.reason);
        }
      });
    }

    return results;
  }

  /**
   * Generate embedding for a finding
   */
  async generateEmbedding(finding: FindingContext): Promise<number[]> {
    await this.ensureProvider();
    const text = this.buildEmbeddingText(finding);
    return this.provider.generateEmbedding(text);
  }

  /**
   * Find similar findings using embeddings
   */
  async findSimilarFindings(
    finding: FindingContext,
    projectId: string,
    limit: number = 5
  ): Promise<SimilarFinding[]> {
    await this.ensureProvider();
    try {
      const embedding = await this.generateEmbedding(finding);

      // Query pgvector for similar embeddings
      const query = `
        SELECT 
          id,
          finding_id,
          1 - (embedding <=> $1) as similarity,
          title,
          scanner,
          severity
        FROM finding_embeddings
        WHERE finding_id != $2
        ORDER BY embedding <=> $1
        LIMIT $3
      `;

      const result = await pgClient.query(query, [
        `[${embedding.join(',')}]`,
        finding.ruleId,
        limit,
      ]);

      return result.rows.map(row => ({
        findingId: row.finding_id,
        similarity: parseFloat(row.similarity),
        title: row.title,
        scanner: row.scanner,
        severity: row.severity,
      }));
    } catch (error) {
      console.error('Similarity search failed:', error);
      return [];
    }
  }

  /**
   * Get AI service status
   */
  async getStatus(): Promise<{
    available: boolean;
    provider: string;
    model: string;
    cacheSize: number;
  }> {
    await this.ensureProvider();
    const available = await this.provider.isAvailable();
    return {
      available,
      provider: this.config.provider,
      model: this.config.model,
      cacheSize: this.cache.size,
    };
  }

  /**
   * Clear the analysis cache
   */
  clearCache(): void {
    this.cache.clear();
    console.log('AI analysis cache cleared');
  }

  private generateFingerprint(finding: FindingContext): string {
    const data = `${finding.ruleId}:${finding.filePath}:${finding.severity}:${finding.title}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private buildEmbeddingText(finding: FindingContext): string {
    return `
      ${finding.title}
      ${finding.description || ''}
      ${finding.remediation || ''}
      Language: ${finding.language}
      Scanner: ${finding.scanner}
      Severity: ${finding.severity}
      ${finding.cveIds?.join(' ') || ''}
      ${finding.cweIds?.join(' ') || ''}
    `.trim();
  }

  private parseAnalysis(raw: string): AIAnalysisResult['analysis'] {
    try {
      const parsed = JSON.parse(raw);
      return {
        explanation: parsed.explanation || 'Unable to generate explanation',
        attackVector: parsed.attackVector || 'Unable to analyze attack vector',
        impactAssessment: parsed.impactAssessment || 'Unable to assess impact',
        falsePositiveLikelihood: parsed.falsePositiveLikelihood || 'medium',
        confidence: parsed.confidence || 50,
      };
    } catch {
      return {
        explanation: raw.slice(0, 500),
        attackVector: 'Analysis format unexpected',
        impactAssessment: 'Unable to parse analysis',
        falsePositiveLikelihood: 'medium',
        confidence: 0,
      };
    }
  }

  private parseRemediation(raw: string): AIAnalysisResult['suggestions'] {
    try {
      const parsed = JSON.parse(raw);
      return {
        codeFix: parsed.codeFix,
        remediationSteps: parsed.remediationSteps || [],
        libraryAlternatives: parsed.libraryAlternatives,
        configurationFix: parsed.configurationFix,
      };
    } catch {
      return {
        remediationSteps: ['Review the finding manually', 'Consult security team'],
      };
    }
  }

  private calculatePrioritization(
    finding: FindingContext,
    analysis: AIAnalysisResult['analysis']
  ): AIAnalysisResult['prioritization'] {
    // Base score from severity
    const severityScore = {
      CRITICAL: 100,
      HIGH: 80,
      MEDIUM: 60,
      LOW: 40,
      INFO: 20,
    }[finding.severity] || 50;

    // Adjust based on false positive likelihood
    const fpAdjustment = {
      low: -10,
      medium: 0,
      high: +20,
    }[analysis.falsePositiveLikelihood] || 0;

    // Adjust based on AI confidence
    const confidenceAdjustment = (analysis.confidence - 50) * 0.2;

    const rawScore = severityScore + fpAdjustment + confidenceAdjustment;

    // Determine priority
    let priority: 'P0' | 'P1' | 'P2' | 'P3';
    let businessImpact: 'low' | 'medium' | 'high' | 'critical';
    let exploitabilityScore: number;

    if (rawScore >= 85) {
      priority = 'P0';
      businessImpact = 'critical';
      exploitabilityScore = 0.9;
    } else if (rawScore >= 70) {
      priority = 'P1';
      businessImpact = 'high';
      exploitabilityScore = 0.7;
    } else if (rawScore >= 50) {
      priority = 'P2';
      businessImpact = 'medium';
      exploitabilityScore = 0.5;
    } else {
      priority = 'P3';
      businessImpact = 'low';
      exploitabilityScore = 0.3;
    }

    return {
      businessImpact,
      exploitabilityScore,
      recommendedPriority: priority,
      reasoning: `Based on severity (${finding.severity}), false positive likelihood (${analysis.falsePositiveLikelihood}), and AI confidence (${analysis.confidence}%)`,
    };
  }

  private async storeAnalysis(
    fingerprint: string,
    finding: FindingContext,
    result: AIAnalysisResult
  ): Promise<void> {
    try {
      await pgClient.query(
        `INSERT INTO ai_analyses 
          (fingerprint, finding_rule_id, finding_file, severity, analysis, suggestions, prioritization, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (fingerprint) DO NOTHING`,
        [
          fingerprint,
          finding.ruleId,
          finding.filePath,
          finding.severity,
          JSON.stringify(result.analysis),
          JSON.stringify(result.suggestions),
          JSON.stringify(result.prioritization),
          JSON.stringify(result.metadata),
        ]
      );
    } catch (error) {
      console.error('Failed to store AI analysis:', error);
    }
  }
}

// Singleton instance
let aiService: AIAnalysisService | null = null;

export function getAIAnalysisService(): AIAnalysisService {
  if (!aiService) {
    aiService = new AIAnalysisService();
  }
  return aiService;
}
