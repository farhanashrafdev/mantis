import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { ConfigLoader } from './config-loader.js';
import { SeverityLevel, OutputFormat } from '../types/types.js';

// Use an isolated temp dir so the tests never find a real mantis.config.yaml
// that may have been generated in the project root during local development.
const isolatedDir = mkdtempSync(`${tmpdir()}/mantis-test-`);

describe('ConfigLoader', () => {
    it('loads default configuration when no overrides are provided', async () => {
        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({});

        expect(config.target.url).toBe('');
        expect(config.target.method).toBe('POST');
        expect(config.scan.severityThreshold).toBe(SeverityLevel.Low);
        expect(config.output.format).toBe(OutputFormat.Table);
        expect(config.output.verbose).toBe(false);
    });

    it('merges CLI overrides correctly', async () => {
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
        process.env.MANTIS_AUTH_TOKEN = 'test-token';
        const loader = new ConfigLoader(isolatedDir);
        const config = await loader.buildConfig({});

        expect(config.target.authToken).toBe('test-token');
        delete process.env.MANTIS_AUTH_TOKEN;
    });
});
