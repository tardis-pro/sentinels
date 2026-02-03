import { AIAnalysisConfig, AIAnalysisResult, FindingContext, SimilarFinding, AIProvider } from './types';
import { getDefaultConfig } from './types';

/**
 * AI Provider Interface
 * Each provider implements these methods for LLM interaction
 */
export interface AIProviderClient {
  provider: AIProvider;
  isAvailable(): Promise<boolean>;
  analyzeFinding(context: FindingContext): Promise<string>;
  generateRemediation(context: FindingContext): Promise<string>;
  generateEmbedding(text: string): Promise<number[]>;
  generateEmbeddings(texts: string[]): Promise<number[][]>;
  countTokens(text: string): Promise<number>;
  close(): Promise<void>;
}

// Provider implementations
export { OllamaProvider } from './providers/ollama';
export { OpenAIProvider } from './providers/openai';
export { AnthropicProvider } from './providers/anthropic';

let defaultProvider: AIProviderClient | null = null;

/**
 * Get or create the default AI provider client
 */
export async function getAIProvider(config?: AIAnalysisConfig): Promise<AIProviderClient> {
  if (defaultProvider) {
    return defaultProvider;
  }

  const cfg = config || getDefaultConfig();

  switch (cfg.provider) {
    case 'ollama':
      const { OllamaProvider } = await import('./providers/ollama');
      defaultProvider = new OllamaProvider(cfg);
      break;
    case 'openai':
      const { OpenAIProvider } = await import('./providers/openai');
      defaultProvider = new OpenAIProvider(cfg);
      break;
    case 'anthropic':
      const { AnthropicProvider } = await import('./providers/anthropic');
      defaultProvider = new AnthropicProvider(cfg);
      break;
    default:
      throw new Error(`Unsupported AI provider: ${cfg.provider}`);
  }

  return defaultProvider;
}

/**
 * Check if AI service is available
 */
export async function isAIServiceAvailable(config?: AIAnalysisConfig): Promise<boolean> {
  try {
    const provider = await getAIProvider(config);
    return await provider.isAvailable();
  } catch {
    return false;
  }
}

/**
 * Reset the default provider (useful for testing or config changes)
 */
export async function resetAIProvider(): Promise<void> {
  if (defaultProvider) {
    await defaultProvider.close();
    defaultProvider = null;
  }
}

/**
 * Create a specific provider client for one-off operations
 */
export async function createProvider(config: AIAnalysisConfig): Promise<AIProviderClient> {
  switch (config.provider) {
    case 'ollama':
      const { OllamaProvider } = await import('./providers/ollama');
      return new OllamaProvider(config);
    case 'openai':
      const { OpenAIProvider } = await import('./providers/openai');
      return new OpenAIProvider(config);
    case 'anthropic':
      const { AnthropicProvider } = await import('./providers/anthropic');
      return new AnthropicProvider(config);
    default:
      throw new Error(`Unsupported AI provider: ${config.provider}`);
  }
}
