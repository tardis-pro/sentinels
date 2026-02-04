import { AIAnalysisConfig, FindingContext } from '../types';
import { AIProviderClient } from '../index';

/**
 * OpenAI Provider for cloud LLM inference
 * Supports GPT-4o, GPT-4 Turbo, and GPT-3.5 Turbo
 */
export class OpenAIProvider implements AIProviderClient {
  provider = 'openai' as const;
  private config: AIAnalysisConfig;
  private apiKey: string;
  private baseUrl: string;

  constructor(config: AIAnalysisConfig) {
    this.config = config;
    this.apiKey = config.apiKey || process.env.OPENAI_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.openai.com/v1';
    
    if (!this.apiKey) {
      throw new Error('OpenAI API key is required. Set OPENAI_API_KEY environment variable.');
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/models`, {
        headers: { Authorization: `Bearer ${this.apiKey}` },
        signal: AbortSignal.timeout(10000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async analyzeFinding(context: FindingContext): Promise<string> {
    const prompt = this.buildAnalysisPrompt(context);
    return this.complete(prompt, 'gpt-4o');
  }

  async generateRemediation(context: FindingContext): Promise<string> {
    const prompt = this.buildRemediationPrompt(context);
    return this.complete(prompt, 'gpt-4o');
  }

  async generateEmbedding(text: string): Promise<number[]> {
    const response = await fetch(`${this.baseUrl}/embeddings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: 'text-embedding-3-small',
        input: text,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI embedding failed: ${error}`);
    }

    const data = await response.json();
    return data.data[0].embedding;
  }

  async generateEmbeddings(texts: string[]): Promise<number[][]> {
    const response = await fetch(`${this.baseUrl}/embeddings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: 'text-embedding-3-small',
        input: texts,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI embedding failed: ${error}`);
    }

    const data = await response.json();
    return data.data.map((item: any) => item.embedding);
  }

  async countTokens(text: string): Promise<number> {
    // OpenAI tokenizer approximation
    // Using the tiktoken library would be more accurate but this is a reasonable estimate
    const words = text.split(/\s+/).length;
    return Math.ceil(words * 1.33);
  }

  async close(): Promise<void> {
    // No cleanup needed for HTTP-based API
  }

  private async complete(prompt: string, model: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature: this.config.temperature || 0.3,
        max_tokens: this.config.maxTokens || 2048,
        response_format: { type: 'json_object' },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error: ${error}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
  }

  private buildAnalysisPrompt(context: FindingContext): string {
    return `You are a senior security analyst. Analyze this vulnerability finding.

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

Provide JSON with: explanation, attackVector, impactAssessment, falsePositiveLikelihood (low/medium/high), confidence (0-100).`;
  }

  private buildRemediationPrompt(context: FindingContext): string {
    return `You are a senior security engineer. Generate remediation guidance.

## Vulnerability
- Title: ${context.title}
- Severity: ${context.severity}
- Scanner: ${context.scanner}
- File: ${context.filePath}
- Language: ${context.language}
${context.projectType ? `- Project: ${context.projectType}` : ''}
${context.dependencies?.length ? `- Deps: ${context.dependencies.join(', ')}` : ''}

## Code
\`\`\`${context.language}
${context.codeSnippet}
\`\`\`

Provide JSON with: codeFix, remediationSteps (array), libraryAlternatives (array), configurationFix.`;
  }
}
