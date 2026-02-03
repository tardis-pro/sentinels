import { 
  PluginMetadata, 
  ScannerPlugin, 
  ParserPlugin, 
  PluginType,
  PluginConfig,
  PluginPermissions 
} from './types';

export class PluginRegistry {
  private plugins: Map<string, PluginMetadata> = new Map();
  private pluginConfigs: Map<string, PluginConfig> = new Map();

  registerPlugin(metadata: PluginMetadata): void {
    if (this.plugins.has(metadata.id)) {
      console.warn(`Plugin ${metadata.id} already registered, overwriting`);
    }
    this.plugins.set(metadata.id, metadata);
  }

  unregisterPlugin(pluginId: string): void {
    this.plugins.delete(pluginId);
    this.pluginConfigs.delete(pluginId);
  }

  getPlugin(pluginId: string): PluginMetadata | undefined {
    return this.plugins.get(pluginId);
  }

  getAllPlugins(): PluginMetadata[] {
    return Array.from(this.plugins.values());
  }

  getPluginsByType(type: PluginType): PluginMetadata[] {
    return this.getAllPlugins().filter(p => p.type === type);
  }

  isPluginInstalled(pluginId: string): boolean {
    return this.plugins.has(pluginId);
  }

  configurePlugin(pluginId: string, config: Record<string, any>): void {
    const existing = this.pluginConfigs.get(pluginId);
    if (existing) {
      existing.settings = { ...existing.settings, ...config };
      this.pluginConfigs.set(pluginId, existing);
    }
  }

  getPluginConfig(pluginId: string): PluginConfig | undefined {
    return this.pluginConfigs.get(pluginId);
  }

  async validatePlugin(plugin: PluginMetadata): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    if (!plugin.id || !plugin.name || !plugin.version) {
      errors.push('Missing required metadata fields');
    }

    if (!['scanner', 'parser', 'enrichment', 'notification', 'report'].includes(plugin.type)) {
      errors.push('Invalid plugin type');
    }

    return { valid: errors.length === 0, errors };
  }
}

export class PluginSandbox {
  private registry: PluginRegistry;

  constructor(registry: PluginRegistry) {
    this.registry = registry;
  }

  createSandboxEnvironment(permissions: PluginPermissions): Record<string, any> {
    const env: Record<string, any> = {
      console: {
        log: (...args: any[]) => console.log('[Plugin]', ...args),
        warn: (...args: any[]) => console.warn('[Plugin]', ...args),
        error: (...args: any[]) => console.error('[Plugin]', ...args),
      },
      fs: permissions.filesystem === 'none' ? undefined : {
        readFile: require('fs').readFileSync,
      },
      fetch: permissions.network ? require('node-fetch') : undefined,
    };

    return env;
  }

  async loadPluginFromSource(source: string, permissions: PluginPermissions): Promise<PluginMetadata> {
    // This would load and evaluate plugin code in a sandbox
    // For now, return a placeholder
    throw new Error('Plugin loading from source not yet implemented');
  }

  isolatePluginExecution<T>(
    plugin: PluginMetadata, 
    fn: () => Promise<T>,
    permissions: PluginPermissions
  ): Promise<T> {
    const sandbox = this.createSandboxEnvironment(permissions);
    
    // In a real implementation, this would use VM2, Docker, or gVisor
    // For now, just execute with context
    return fn();
  }
}

export function createPluginRegistry(): PluginRegistry {
  return new PluginRegistry();
}

export function createPluginSandbox(registry: PluginRegistry): PluginSandbox {
  return new PluginSandbox(registry);
}
