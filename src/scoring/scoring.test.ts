import { describe, it, expect } from 'vitest';
import { ALVSSEngine } from './scoring.js';
import { SeverityLevel, AttackCategory } from '../types/types.js';

describe('ALVSSEngine', () => {
    const engine = new ALVSSEngine();

    it('scores a critical finding correctly', () => {
        const finding = {
            id: '1',
            pluginId: 'test',
            category: AttackCategory.PromptInjection,
            title: 'Test',
            description: 'Test',
            severity: SeverityLevel.Critical,
            riskScore: 0, // Ignored by engine
            attackPrompt: 'test',
            response: 'test',
            evidence: 'test',
            confidence: 1.0,
            remediation: 'test',
            timestamp: 'test',
            reproducible: true,
            attempts: 1,
            successes: 1,
        };

        const result = engine.score(finding);
        expect(result.severity).toBe(SeverityLevel.Critical);
        expect(result.score).toBeGreaterThanOrEqual(9.0);
    });

    it('scores a low finding correctly', () => {
        const finding = {
            id: '2',
            pluginId: 'test',
            category: AttackCategory.DataLeakage,
            title: 'Test',
            description: 'Test',
            severity: SeverityLevel.Low,
            riskScore: 0,
            attackPrompt: 'test',
            response: 'test',
            evidence: 'test',
            confidence: 0.5,
            remediation: 'test',
            timestamp: 'test',
            reproducible: false,
            attempts: 5,
            successes: 1,
        };

        const result = engine.score(finding);
        expect(result.severity).toBe(SeverityLevel.Medium);
        expect(result.score).toBeLessThan(7.0);
    });

    it('calculates aggregate risk score properly using scoreBatch', () => {
        const findings = [
            {
                id: '1', pluginId: 'test', category: AttackCategory.PromptInjection, title: 'T1', description: '',
                severity: SeverityLevel.Critical, riskScore: 0, attackPrompt: '', response: '', evidence: '',
                confidence: 1.0, remediation: '', timestamp: '', reproducible: true, attempts: 1, successes: 1,
            },
            {
                id: '2', pluginId: 'test', category: AttackCategory.PromptInjection, title: 'T2', description: '',
                severity: SeverityLevel.High, riskScore: 0, attackPrompt: '', response: '', evidence: '',
                confidence: 0.9, remediation: '', timestamp: '', reproducible: true, attempts: 2, successes: 2,
            }
        ];

        const batchResult = engine.scoreBatch(findings);
        expect(batchResult.individual.length).toBe(2);
        expect(batchResult.aggregate).toBeGreaterThanOrEqual(8.0);
        expect(batchResult.aggregateSeverity).toBe(SeverityLevel.Critical);
    });
});
