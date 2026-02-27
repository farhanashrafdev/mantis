/**
 * mantis — Plugin Registry
 *
 * Handles dynamic discovery, validation, registration, and retrieval
 * of attack plugins. Plugins are loaded from the plugins directory
 * and validated against the Plugin interface contract.
 */

import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Plugin, AttackCategory } from '../types/types.js';

/** Plugin validation error */
export class PluginValidationError extends Error {
    constructor(
        public readonly pluginPath: string,
        message: string,
    ) {
        super(`Plugin validation failed [${pluginPath}]: ${message}`);
        this.name = 'PluginValidationError';
    }
}

/**
 * PluginRegistry — discovers, validates, and manages attack plugins.
 *
 * Usage:
 *   const registry = new PluginRegistry();
 *   await registry.discover('./src/plugins');
 *   const plugins = registry.getByCategory(AttackCategory.PromptInjection);
 */
export class PluginRegistry {
    private plugins: Map<string, Plugin> = new Map();

    /** Get all registered plugins */
    getAll(): Plugin[] {
        return Array.from(this.plugins.values());
    }

    /** Get a plugin by its ID */
    getById(id: string): Plugin | undefined {
        return this.plugins.get(id);
    }

    /** Get all plugins in a given category */
    getByCategory(category: AttackCategory): Plugin[] {
        return this.getAll().filter((p) => p.meta.category === category);
    }

    /** Get all plugins matching a list of IDs or category names */
    getFiltered(include: string[], exclude: string[]): Plugin[] {
        let plugins = this.getAll();

        if (include.length > 0) {
            plugins = plugins.filter(
                (p) =>
                    include.includes(p.meta.id) ||
                    include.includes(p.meta.category),
            );
        }

        if (exclude.length > 0) {
            plugins = plugins.filter(
                (p) =>
                    !exclude.includes(p.meta.id) &&
                    !exclude.includes(p.meta.category),
            );
        }

        return plugins;
    }

    /** Get count of registered plugins */
    get count(): number {
        return this.plugins.size;
    }

    /** Get unique categories that have registered plugins */
    getCategories(): AttackCategory[] {
        const categories = new Set<AttackCategory>();
        for (const plugin of this.plugins.values()) {
            categories.add(plugin.meta.category);
        }
        return Array.from(categories);
    }

    /**
     * Discover and load plugins from a directory.
     *
     * Expected structure:
     *   plugins/
     *     prompt-injection/
     *       system-override.ts
     *       jailbreak.ts
     *     data-leakage/
     *       hidden-prompt.ts
     *
     * Each .ts/.js file must default-export a Plugin object.
     */
    async discover(pluginsDir: string): Promise<void> {
        const categoryDirs = await readdir(pluginsDir, { withFileTypes: true });

        for (const dir of categoryDirs) {
            if (!dir.isDirectory()) continue;
            if (dir.name.startsWith('.') || dir.name.startsWith('_')) continue;

            const categoryPath = join(pluginsDir, dir.name);
            const pluginFiles = await readdir(categoryPath, { withFileTypes: true });

            for (const file of pluginFiles) {
                if (!file.isFile()) continue;
                if (!file.name.endsWith('.ts') && !file.name.endsWith('.js')) continue;
                if (file.name.endsWith('.d.ts')) continue;
                if (file.name.startsWith('.') || file.name.startsWith('_')) continue;
                if (file.name.endsWith('.test.ts') || file.name.endsWith('.spec.ts')) continue;

                const filePath = join(categoryPath, file.name);
                await this.loadPlugin(filePath);
            }
        }
    }

    /**
     * Load and register a single plugin from a file path.
     * The file must default-export an object implementing the Plugin interface.
     */
    async loadPlugin(filePath: string): Promise<void> {
        try {
            const fileUrl = pathToFileURL(filePath).href;
            const module = await import(fileUrl) as { default?: Plugin };

            if (!module.default) {
                throw new PluginValidationError(
                    filePath,
                    'File does not have a default export',
                );
            }

            const plugin = module.default;
            this.validate(plugin, filePath);
            this.register(plugin);
        } catch (error) {
            if (error instanceof PluginValidationError) {
                throw error;
            }
            throw new PluginValidationError(
                filePath,
                `Failed to load: ${error instanceof Error ? error.message : String(error)}`,
            );
        }
    }

    /** Register a plugin directly (for programmatic registration) */
    register(plugin: Plugin): void {
        if (this.plugins.has(plugin.meta.id)) {
            throw new PluginValidationError(
                plugin.meta.id,
                `Duplicate plugin ID: ${plugin.meta.id}`,
            );
        }
        this.plugins.set(plugin.meta.id, plugin);
    }

    /** Validate that a plugin implements the required interface */
    private validate(plugin: Plugin, filePath: string): void {
        const errors: string[] = [];

        // Validate meta
        if (!plugin.meta) errors.push('Missing "meta" property');
        else {
            if (!plugin.meta.id) errors.push('Missing "meta.id"');
            if (!plugin.meta.name) errors.push('Missing "meta.name"');
            if (!plugin.meta.description) errors.push('Missing "meta.description"');
            if (!plugin.meta.category) errors.push('Missing "meta.category"');
            if (!plugin.meta.version) errors.push('Missing "meta.version"');
        }

        // Validate prompts
        if (!Array.isArray(plugin.prompts)) {
            errors.push('"prompts" must be an array');
        } else if (plugin.prompts.length === 0) {
            errors.push('"prompts" array is empty');
        }

        // Validate methods
        if (typeof plugin.initialize !== 'function') errors.push('Missing "initialize" method');
        if (typeof plugin.execute !== 'function') errors.push('Missing "execute" method');
        if (typeof plugin.analyze !== 'function') errors.push('Missing "analyze" method');
        if (typeof plugin.teardown !== 'function') errors.push('Missing "teardown" method');

        if (errors.length > 0) {
            throw new PluginValidationError(
                filePath,
                errors.join('; '),
            );
        }
    }

    /** Clear all registered plugins */
    clear(): void {
        this.plugins.clear();
    }

    /** Get a summary of registered plugins for display */
    getSummary(): Array<{ id: string; name: string; category: string; prompts: number }> {
        return this.getAll().map((p) => ({
            id: p.meta.id,
            name: p.meta.name,
            category: p.meta.category,
            prompts: p.prompts.length,
        }));
    }
}
