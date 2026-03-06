import { describe, it, expect } from 'vitest';
import { JSONReporter } from './json-reporter.js';
import type { ScanReport} from '../types/types.js';
import { SeverityLevel, AttackCategory } from '../types/types.js';

describe('JSONReporter', () => {
    const report: ScanReport = {
        meta: {
            scanId: 'test-scan-123',
            targetUrl: 'https://example.com/api',
            startedAt: new Date().toISOString(),
            completedAt: new Date().toISOString(),
            durationMs: 1500,
            mantisVersion: '1.0.0',
            pluginsExecuted: 1,
            totalPromptsSent: 1,
        },
        summary: {
            totalFindings: 1,
            criticalCount: 0,
            highCount: 1,
            mediumCount: 0,
            lowCount: 0,
            infoCount: 0,
            categoryScores: {
                [AttackCategory.PromptInjection]: 8.5,
                [AttackCategory.DataLeakage]: 0,
                [AttackCategory.Hallucination]: 0,
                [AttackCategory.ToolExploit]: 0,
            },
            overallRiskScore: 8.5,
            overallSeverity: SeverityLevel.High,
        },
        pluginResults: [],
        findings: [
            {
                id: '1',
                pluginId: 'test-plugin',
                category: AttackCategory.PromptInjection,
                title: 'Test Finding',
                description: 'Test Description',
                severity: SeverityLevel.High,
                riskScore: 8.5,
                attackPrompt: 'inject this',
                response: 'injected',
                evidence: 'match found',
                confidence: 0.9,
                remediation: 'fix it',
                timestamp: new Date().toISOString(),
                reproducible: true,
                attempts: 1,
                successes: 1,
            }
        ],
    };

    it('generates a valid JSON format', async () => {
        const reporter = new JSONReporter();
        const output = await reporter.generate(report);

        expect(output).toBeDefined();
        const parsed = JSON.parse(output);
        expect(parsed.meta.scanId).toBe('test-scan-123');
        expect(parsed.meta.targetUrl).toBe('https://example.com/api');
        expect(parsed.findings.length).toBe(1);
        expect(parsed.summary.overallSeverity).toBe(SeverityLevel.High);
    });
});
