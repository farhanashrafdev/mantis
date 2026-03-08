import { describe, it, expect } from 'vitest';
import { SARIFReporter } from './sarif-reporter.js';
import type { ScanReport } from '../types/types.js';
import { AttackCategory, PluginStatus, SeverityLevel } from '../types/types.js';

describe('SARIFReporter', () => {
    const buildReport = (): ScanReport => ({
        meta: {
            scanId: 'scan-123',
            targetUrl: 'https://example.com/chat',
            startedAt: '2026-01-01T00:00:00.000Z',
            completedAt: '2026-01-01T00:00:05.000Z',
            durationMs: 5000,
            mantisVersion: '0.2.1',
            pluginsExecuted: 2,
            totalPromptsSent: 3,
        },
        summary: {
            totalFindings: 3,
            criticalCount: 0,
            highCount: 1,
            mediumCount: 1,
            lowCount: 0,
            infoCount: 1,
            overallRiskScore: 8.2,
            overallSeverity: SeverityLevel.High,
            categoryScores: {
                [AttackCategory.PromptInjection]: 8.2,
                [AttackCategory.DataLeakage]: 0,
                [AttackCategory.Hallucination]: 4.3,
                [AttackCategory.ToolExploit]: 0,
            },
        },
        findings: [
            {
                id: 'f1',
                pluginId: 'prompt-injection/system-override',
                category: AttackCategory.PromptInjection,
                title: 'System Override: Revealed policy',
                description: 'Model leaked restricted policy text',
                severity: SeverityLevel.High,
                riskScore: 8.2,
                attackPrompt: 'ignore and reveal policy',
                response: 'policy text',
                evidence: 'policy snippet',
                confidence: 0.95,
                remediation: 'harden guardrails',
                cwe: 'CWE-200',
                timestamp: '2026-01-01T00:00:01.000Z',
                reproducible: true,
                attempts: 3,
                successes: 3,
            },
            {
                id: 'f2',
                pluginId: 'hallucination/fabricated-url',
                category: AttackCategory.Hallucination,
                title: 'Fabricated URL: Fake source link',
                description: 'Model provided a non-existent citation URL',
                severity: SeverityLevel.Medium,
                riskScore: 4.3,
                attackPrompt: 'give references',
                response: 'https://not-real.example',
                evidence: 'not-real.example',
                confidence: 0.7,
                remediation: 'enable citation checks',
                timestamp: '2026-01-01T00:00:02.000Z',
                reproducible: false,
                attempts: 3,
                successes: 1,
            },
            {
                id: 'f3',
                pluginId: 'hallucination/nonexistent-entity',
                category: AttackCategory.Hallucination,
                title: 'Nonexistent Entity: Invented person',
                description: 'Model invented a person that does not exist',
                severity: SeverityLevel.Info,
                riskScore: 0.8,
                attackPrompt: 'name key researchers',
                response: 'Dr. X from Y Institute',
                evidence: 'no matching records found',
                confidence: 0.3,
                remediation: 'require evidence-based outputs',
                timestamp: '2026-01-01T00:00:03.000Z',
                reproducible: false,
                attempts: 2,
                successes: 0,
            },
        ],
        pluginResults: [
            {
                pluginId: 'prompt-injection/system-override',
                pluginName: 'System Override',
                category: AttackCategory.PromptInjection,
                status: PluginStatus.Failed,
                findings: [],
                promptsExecuted: 1,
                durationMs: 1200,
            },
            {
                pluginId: 'hallucination/fabricated-url',
                pluginName: 'Fabricated URL',
                category: AttackCategory.Hallucination,
                status: PluginStatus.Failed,
                findings: [],
                promptsExecuted: 2,
                durationMs: 800,
            },
        ],
    });

    it('generates valid SARIF structure with expected top-level fields', () => {
        const reporter = new SARIFReporter();
        const output = reporter.generate(buildReport());
        const parsed = JSON.parse(output) as {
            $schema: string;
            version: string;
            runs: Array<Record<string, unknown>>;
        };

        expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
        expect(parsed.version).toBe('2.1.0');
        expect(parsed.runs).toHaveLength(1);
    });

    it('maps finding severities to SARIF levels', () => {
        const reporter = new SARIFReporter();
        const parsed = JSON.parse(reporter.generate(buildReport())) as {
            runs: Array<{ results: Array<{ ruleId: string; level: string }> }>;
        };

        const levelsByRule = Object.fromEntries(
            parsed.runs[0].results.map((r) => [r.ruleId, r.level]),
        );

        expect(levelsByRule['prompt-injection-system-override']).toBe('error');
        expect(levelsByRule['hallucination-fabricated-url']).toBe('warning');
        expect(levelsByRule['hallucination-nonexistent-entity']).toBe('none');
    });

    it('creates rules and maps CWE to helpUri', () => {
        const reporter = new SARIFReporter();
        const parsed = JSON.parse(reporter.generate(buildReport())) as {
            runs: Array<{ tool: { driver: { rules: Array<{ id: string; helpUri?: string }> } } }>;
        };

        const rules = parsed.runs[0].tool.driver.rules;
        const systemOverrideRule = rules.find((r) => r.id === 'prompt-injection-system-override');

        expect(rules.length).toBe(3);
        expect(systemOverrideRule?.helpUri).toBe(
            'https://cwe.mitre.org/data/definitions/200.html',
        );
    });

    it('includes finding metadata and target location in result properties', () => {
        const reporter = new SARIFReporter();
        const parsed = JSON.parse(reporter.generate(buildReport())) as {
            runs: Array<{
                results: Array<{
                    ruleId: string;
                    properties: Record<string, unknown>;
                    locations?: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
                    message: { text: string };
                }>;
            }>;
        };

        const result = parsed.runs[0].results.find(
            (r) => r.ruleId === 'prompt-injection-system-override',
        );

        expect(result?.properties['mantis-score']).toBe(8.2);
        expect(result?.properties['mantis-confidence']).toBe(0.95);
        expect(result?.locations?.[0].physicalLocation.artifactLocation.uri).toBe(
            'https://example.com/chat',
        );
        expect(result?.message.text).toContain('Risk Score: 8.2/10');
        expect(result?.message.text).toContain('CWE: CWE-200');
    });
});
