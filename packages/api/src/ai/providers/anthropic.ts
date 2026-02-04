import { AIAnalysisConfig, FindingContext } from '../types';
import { AIProviderClient } from '../index';

/**
 * Anthropic Provider for Claude models
 * Supports Claude 3.5 Sonnet, Claude 3 Opus, etc.
 */
export class AnthropicProvider implements AIProviderClient {
  provider = 'anthropic' as const;
  private config: AIAnalysisConfig;
  private apiKey: string;
  private baseUrl: string;

  constructor(config: AIAnalysisConfig) {
    this.config = config;
    this.apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';

    if (!this.apiKey) {
      throw new Error('Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable.');
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/models`, {
        headers: { 'x-api-key': this.apiKey },
        signal: AbortSignal.timeout(10000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async analyzeFinding(context: FindingContext): Promise<string> {
    const prompt = this.buildAnalysisPrompt(context);
    return this.complete(prompt, 'claude-sonnet-4-20250514');
  }

  async generateRemediation(context: FindingContext): Promise<string> {
    const prompt = this.buildRemediationPrompt(context);
    return this.complete(prompt, 'claude-sonnet-4-20250514');
  }

  async generateEmbedding(text: string): Promise<number[]> {
    // Anthropic doesn't have a native embeddings API
    // Fall back to OpenAI or local embeddings
    throw new Error('Embeddings not natively supported by Anthropic. Use OpenAI or Ollama provider.');
  }

  async generateEmbeddings(texts: string[]): Promise<number[][]> {
    throw new Error('Embeddings not natively supported by Anthropic. Use OpenAI or Ollama provider.');
  }

  async countTokens(text: string): Promise<number> {
    // Claude tokenizer approximation
    const words = text.split(/\s+/).length;
    return Math.ceil(words * 1.2);
  }

  async close(): Promise<void> {
    // No cleanup needed for HTTP-based API
  }

  private async complete(prompt: string, model: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/v1/complete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        prompt,
        max_tokens_to_sample: this.config.maxTokens || 2048,
        temperature: this.config.temperature || 0.3,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Anthropic API error: ${error}`);
    }

    const data = await response.json();
    return data.completion;
  }

  private buildAnalysisPrompt(context: FindingContext): string {
    return `\n\nHuman: You are a senior security analyst. Analyze this vulnerability finding.

## Vulnerability
- Title: ${context.title}
- Severity: ${context.severity}
- Scanner: ${context.scanner}
- File: ${context.filePath}
- Language: ${context.language}
${context.cveIds?.length ? `- CVEs: ${context.cveIds.join(', ')}` : ''}
${context.cweIds?.length ? `- CWEs: ${context.cweIds.join(', ')}` : ''}

## Code
\`\`\`${context.language}
${context.codeSnippet}
\`\`\`

${context.description ? `## Description\n${context.description}\n` : ''}

Provide your analysis as JSON with these fields:
- explanation: Plain-English explanation
- attackVector: Exploitation method
- impactAssessment: Business impact
- falsePositiveLikelihood: low, medium, or high
- confidence: number between 0-100

${'\n\nAssistant: '}`;
  }

  private buildRemediationPrompt(context: FindingContext): string {
    return `\n\nHuman: You are a senior security engineer. Generate remediation guidance.

## Vulnerability
- Title: ${context.title}
- Severity: ${context.severity}
- Scanner: ${context.scanner}
- File: ${context.filePath}
- Language: ${context.language}
${context.projectType ? `- Project: ${context.projectType}` : ''}
${context.dependencies?.length ? `- Dependencies: ${context.dependencies.join(', ')}` : ''}

## Code
\`\`\`${context.language}
${context.codeSnippet}
\`\`\`

Provide remediation as JSON with:
- codeFix: Suggested code change
- remediationSteps: Array of step-by-step instructions
- libraryAlternatives: Array of safer alternatives
- configurationFix: Configuration change if applicable

${'\n\nAssistant: '}`;
  }
}
