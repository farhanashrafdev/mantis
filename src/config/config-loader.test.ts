import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ConfigLoader, ConfigValidationError } from './config-loader.js';
import { SeverityLevel, OutputFormat } from '../types/types.js';

const makeTempDir = (): string => mkdtempSync(`${tmpdir()}/mantis-test-`);

describe('ConfigLoader', () => {
    it('loads default configuration when no overrides are provided', async () => {
        const isolatedDir = makeTempDir();
        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({});

        expect(config.target.url).toBe('');
        expect(config.target.method).toBe('POST');
        expect(config.scan.severityThreshold).toBe(SeverityLevel.Low);
        expect(config.output.format).toBe(OutputFormat.Table);
        expect(config.output.verbose).toBe(false);
    });

    it('merges CLI overrides correctly', async () => {
        const isolatedDir = makeTempDir();
        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({
            cliOverrides: {
                target: { url: 'https://example.com/api', method: 'POST', headers: {}, promptField: '', responseField: '' },
                output: { format: OutputFormat.JSON, verbose: true, redactResponses: true },
                scan: { severityThreshold: SeverityLevel.High, timeoutMs: 0, maxRetries: 0, retryDelayMs: 0, rateLimit: 0, reproducibilityAttempts: 0 },
                modules: { include: [], exclude: [] },
                scoring: { weights: { exploitability: 0, impact: 0, dataSensitivity: 0, reproducibility: 0, modelCompliance: 0 } }
            }
        });

        expect(config.target.url).toBe('https://example.com/api');
        expect(config.output.format).toBe(OutputFormat.JSON);
        expect(config.output.verbose).toBe(true);
        expect(config.scan.severityThreshold).toBe(SeverityLevel.High);
    });

    it('handles environments variables for auth token', async () => {
        const isolatedDir = makeTempDir();
        process.env.MANTIS_AUTH_TOKEN = 'test-token';
        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({});

        expect(config.target.authToken).toBe('test-token');
        delete process.env.MANTIS_AUTH_TOKEN;
    });

    it('throws a validation error for invalid YAML', async () => {
        const isolatedDir = makeTempDir();
        const badPath = join(isolatedDir, 'bad.yaml');
        await writeFile(badPath, 'version: 1.0\ntarget: [', 'utf-8');

        const loader = new ConfigLoader(isolatedDir);
        await expect(loader.loadFile('bad.yaml')).rejects.toBeInstanceOf(ConfigValidationError);
    });

    it('throws when scoring weights in config do not sum to 1.0', async () => {
        const isolatedDir = makeTempDir();
        const badPath = join(isolatedDir, 'bad-weights.yaml');
        await writeFile(
            badPath,
            [
                'version: "1.0"',
                'target:',
                '  url: "https://example.com"',
                'scoring:',
                '  weights:',
                '    exploitability: 0.4',
                '    impact: 0.4',
                '    dataSensitivity: 0.2',
                '    reproducibility: 0.1',
                '    modelCompliance: 0.1',
            ].join('\n'),
            'utf-8',
        );

        const loader = new ConfigLoader(isolatedDir);
        await expect(loader.loadFile('bad-weights.yaml')).rejects.toThrow(/must sum to 1.0/);
    });

    it('merges profile values on top of base config file', async () => {
        const isolatedDir = makeTempDir();
        const filePath = join(isolatedDir, 'mantis.config.yaml');
        await writeFile(
            filePath,
            [
                'version: "1.0"',
                'target:',
                '  url: "https://base.example.com"',
                'scan:',
                '  timeoutMs: 10000',
                'output:',
                '  format: table',
                'profiles:',
                '  strict:',
                '    scan:',
                '      severityThreshold: high',
                '      reproducibilityAttempts: 5',
                '    output:',
                '      format: sarif',
                '    modules:',
                '      include: ["prompt-injection"]',
            ].join('\n'),
            'utf-8',
        );

        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({ profile: 'strict' });

        expect(config.target.url).toBe('https://base.example.com');
        expect(config.scan.timeoutMs).toBe(10000);
        expect(config.scan.severityThreshold).toBe(SeverityLevel.High);
        expect(config.scan.reproducibilityAttempts).toBe(5);
        expect(config.output.format).toBe(OutputFormat.SARIF);
        expect(config.modules.include).toEqual(['prompt-injection']);
    });

    it('throws when a requested profile does not exist', async () => {
        const isolatedDir = makeTempDir();
        const filePath = join(isolatedDir, 'mantis.config.yaml');
        await writeFile(
            filePath,
            [
                'version: "1.0"',
                'target:',
                '  url: "https://example.com"',
                'profiles:',
                '  safe:',
                '    scan:',
                '      severityThreshold: low',
            ].join('\n'),
            'utf-8',
        );

        const loader = new ConfigLoader(isolatedDir);
        await expect(loader.buildConfig({ profile: 'strict' })).rejects.toThrow(/Profile "strict" not found/);
    });

    it('does not override auth token and target url from env when already provided', async () => {
        const isolatedDir = makeTempDir();
        process.env.MANTIS_AUTH_TOKEN = 'env-token';
        process.env.MANTIS_TARGET_URL = 'https://env.example.com';

        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({
            cliOverrides: {
                target: {
                    url: 'https://cli.example.com',
                    method: 'POST',
                    headers: {},
                    promptField: 'prompt',
                    responseField: 'response',
                    authToken: 'cli-token',
                },
            },
        });

        expect(config.target.url).toBe('https://cli.example.com');
        expect(config.target.authToken).toBe('cli-token');

        delete process.env.MANTIS_AUTH_TOKEN;
        delete process.env.MANTIS_TARGET_URL;
    });

    it('allows env format to override selected output format', async () => {
        const isolatedDir = makeTempDir();
        process.env.MANTIS_FORMAT = 'sarif';

        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({
            cliOverrides: {
                output: {
                    format: OutputFormat.Table,
                    verbose: false,
                    redactResponses: true,
                },
            },
        });

        expect(config.output.format).toBe(OutputFormat.SARIF);
        delete process.env.MANTIS_FORMAT;
    });
});
