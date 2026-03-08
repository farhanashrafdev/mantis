import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PluginRegistry, PluginValidationError } from './plugin-registry.js';
import type { Plugin } from '../types/types.js';
import { AttackCategory } from '../types/types.js';

const makeTempDir = (): string => mkdtempSync(`${tmpdir()}/mantis-registry-test-`);

describe('PluginRegistry', () => {
    const createValidPluginModule = (id: string, category: string): string => [
        'export default {',
        `  meta: { id: "${id}", name: "${id}", description: "desc", category: "${category}", version: "1.0.0", author: "test", tags: ["x"] },`,
        '  prompts: [{ id: "p1", prompt: "x", description: "d", securePatterns: [/safe/i], vulnerablePatterns: [/unsafe/i], severity: "high" }],',
        '  async initialize() {},',
        '  async execute() { return []; },',
        '  analyze() { return { vulnerable: false, confidence: 0, evidence: "", matchedPatterns: [] }; },',
        '  async teardown() {},',
        '};',
    ].join('\n');

    it('discovers no plugins from empty category directories', async () => {
        const dir = makeTempDir();
        await mkdir(join(dir, 'prompt-injection'));

        const registry = new PluginRegistry();
        await registry.discover(dir);

        expect(registry.count).toBe(0);
        expect(registry.getAll()).toEqual([]);
    });

    it('throws for plugin files without default export', async () => {
        const dir = makeTempDir();
        const filePath = join(dir, 'bad-plugin.js');
        await writeFile(filePath, 'export const x = 1;', 'utf-8');

        const registry = new PluginRegistry();
        await expect(registry.loadPlugin(filePath)).rejects.toBeInstanceOf(PluginValidationError);
    });

    it('throws for malformed plugin exports', async () => {
        const dir = makeTempDir();
        const filePath = join(dir, 'malformed-plugin.js');
        await writeFile(filePath, 'export default { meta: {}, prompts: [] };', 'utf-8');

        const registry = new PluginRegistry();
        await expect(registry.loadPlugin(filePath)).rejects.toThrow(/Missing "meta.id"|prompts/);
    });

    it('throws on duplicate plugin IDs during discovery', async () => {
        const dir = makeTempDir();
        const cat1 = join(dir, 'prompt-injection');
        const cat2 = join(dir, 'data-leakage');
        await mkdir(cat1);
        await mkdir(cat2);

        const pluginId = 'duplicate/plugin';
        await writeFile(join(cat1, 'one.js'), createValidPluginModule(pluginId, 'prompt-injection'), 'utf-8');
        await writeFile(join(cat2, 'two.js'), createValidPluginModule(pluginId, 'data-leakage'), 'utf-8');

        const registry = new PluginRegistry();
        await expect(registry.discover(dir)).rejects.toThrow(/Duplicate plugin ID/);
    });

    it('filters plugins by include and exclude lists', () => {
        const registry = new PluginRegistry();

        const makePlugin = (id: string, category: AttackCategory): Plugin => ({
            meta: {
                id,
                name: id,
                description: id,
                category,
                version: '1.0.0',
                author: 'test',
                tags: [],
            },
            prompts: [
                {
                    id: 'p1',
                    prompt: 'x',
                    description: 'x',
                    securePatterns: [/safe/i],
                    vulnerablePatterns: [/unsafe/i],
                    severity: 'high',
                },
            ],
            async initialize() {},
            async execute() {
                return [];
            },
            analyze() {
                return { vulnerable: false, confidence: 0, evidence: '', matchedPatterns: [] };
            },
            async teardown() {},
        });

        registry.register(makePlugin('prompt-injection/system-override', AttackCategory.PromptInjection));
        registry.register(makePlugin('data-leakage/secret-retrieval', AttackCategory.DataLeakage));
        registry.register(makePlugin('hallucination/fabricated-url', AttackCategory.Hallucination));

        const included = registry.getFiltered(['prompt-injection'], []);
        expect(included.map((p) => p.meta.id)).toEqual(['prompt-injection/system-override']);

        const excluded = registry.getFiltered([], [AttackCategory.DataLeakage]);
        expect(excluded.map((p) => p.meta.id)).toEqual([
            'prompt-injection/system-override',
            'hallucination/fabricated-url',
        ]);
    });
});
