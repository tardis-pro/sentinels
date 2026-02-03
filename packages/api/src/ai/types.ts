/**
 * AI-Powered Vulnerability Analysis Service
 * 
 * Provides intelligent vulnerability analysis, remediation suggestions,
 * and prioritization using LLMs (Ollama for local, OpenAI/Anthropic for cloud).
 */

import crypto from 'crypto';
import { UnifiedFinding } from '../parsers';

// AI Provider types
export type AIProvider = 'ollama' | 'openai' | 'anthropic';

export interface AIAnalysisConfig {
  provider: AIProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  temperature?: number;
  maxTokens?: number;
  embeddingModel?: string;
}

export interface FindingContext {
  codeSnippet: string;
  filePath: string;
  language: string;
  dependencies?: string[];
  projectType?: string;
  severity: string;
  scanner: string;
  ruleId: string;
  title: string;
  description?: string;
  remediation?: string;
  cveIds?: string[];
  cweIds?: string[];
}

export interface AIAnalysisResult {
  id: string;
  findingId: string;
  analysis: {
    explanation: string;
    attackVector: string;
    impactAssessment: string;
    falsePositiveLikelihood: 'low' | 'medium' | 'high';
    confidence: number;
  };
  suggestions: {
    codeFix?: string;
    remediationSteps: string[];
    libraryAlternatives?: string[];
    configurationFix?: string;
  };
  prioritization: {
    businessImpact: 'low' | 'medium' | 'high' | 'critical';
    exploitabilityScore: number;
    recommendedPriority: 'P0' | 'P1' | 'P2' | 'P3';
    reasoning: string;
  };
  metadata: {
    model: string;
    provider: AIProvider;
    tokensUsed: number;
    processingTimeMs: number;
    timestamp: string;
  };
}

// Embedding vector for similarity search
export interface FindingEmbedding {
  findingId: string;
  embedding: number[];
  titleEmbedding?: number[];
  descriptionEmbedding?: number[];
  createdAt: string;
}

// Similar finding from vector search
export interface SimilarFinding {
  findingId: string;
  similarity: number;
  title?: string;
  scanner?: string;
  severity?: string;
}

// Cache key for AI analysis
function generateCacheKey(fingerprint: string, config: AIAnalysisConfig): string {
  return crypto.createHash('sha256')
    .update(`${fingerprint}:${config.provider}:${config.model}`)
    .digest('hex')
    .slice(0, 16);
}

// Default configuration
export function getDefaultConfig(): AIAnalysisConfig {
  return {
    provider: process.env.AI_PROVIDER as AIProvider || 'ollama',
    model: process.env.AI_MODEL || 'llama3.2',
    apiKey: process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY,
    baseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    temperature: 0.3,
    maxTokens: 2048,
    embeddingModel: process.env.EMBEDDING_MODEL || 'nomic-embed-text',
  };
}
