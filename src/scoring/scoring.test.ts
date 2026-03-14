import { describe, it, expect } from 'vitest';
import { ALVSSEngine, computeCategoryScores } from './scoring.js';
import type { Finding, ScoringWeights } from '../types/types.js';
import { SeverityLevel, AttackCategory } from '../types/types.js';

describe('ALVSSEngine', () => {
    const engine = new ALVSSEngine();

    const baseFinding = (overrides: Partial<Finding> = {}): Finding => ({
        id: 'f-1',
        pluginId: 'prompt-injection/system-override',
        category: AttackCategory.PromptInjection,
        title: 'Test finding',
        description: 'Test finding description',
        severity: SeverityLevel.High,
        riskScore: 0,
        attackPrompt: 'attack',
        response: 'response',
        evidence: 'evidence',
        confidence: 0.9,
        remediation: 'fix',
        timestamp: new Date().toISOString(),
        reproducible: true,
        attempts: 1,
        successes: 1,
        ...overrides,
    });

    it('scores a critical finding correctly', () => {
        const finding = baseFinding({
            severity: SeverityLevel.Critical,
            confidence: 1.0,
        });

        const result = engine.score(finding);
        expect(result.severity).toBe(SeverityLevel.Critical);
        expect(result.score).toBeGreaterThanOrEqual(9.0);
    });

    it('scores a low finding correctly', () => {
        const finding = baseFinding({
            category: AttackCategory.DataLeakage,
            severity: SeverityLevel.Low,
            confidence: 0.5,
            reproducible: false,
            attempts: 5,
            successes: 1,
        });

        const result = engine.score(finding);
        expect(result.severity).toBe(SeverityLevel.Medium);
        expect(result.score).toBeLessThan(7.0);
    });

    it('maps 6.9 and 7.0 to different severities at the boundary', () => {
        const modelComplianceOnlyWeights: ScoringWeights = {
            exploitability: 0,
            impact: 0,
            dataSensitivity: 0,
            reproducibility: 0,
            modelCompliance: 1,
        };
        const customEngine = new ALVSSEngine(modelComplianceOnlyWeights);

        const justBelow = baseFinding({
            severity: SeverityLevel.High,
            confidence: 0.8625,
        });
        const onBoundary = baseFinding({
            id: 'f-2',
            severity: SeverityLevel.High,
            confidence: 0.875,
        });

        const belowResult = customEngine.score(justBelow);
        const boundaryResult = customEngine.score(onBoundary);

        expect(belowResult.score).toBe(6.9);
        expect(belowResult.severity).toBe(SeverityLevel.Medium);
        expect(boundaryResult.score).toBe(7.0);
        expect(boundaryResult.severity).toBe(SeverityLevel.High);
    });

    it('returns info severity when confidence drives score to zero', () => {
        const modelComplianceOnlyWeights: ScoringWeights = {
            exploitability: 0,
            impact: 0,
            dataSensitivity: 0,
            reproducibility: 0,
            modelCompliance: 1,
        };
        const customEngine = new ALVSSEngine(modelComplianceOnlyWeights);
        const finding = baseFinding({ confidence: 0 });

        const result = customEngine.score(finding);
        expect(result.score).toBe(0);
        expect(result.severity).toBe(SeverityLevel.Info);
    });

    it('throws when weights do not sum to 1.0', () => {
        const badWeights: ScoringWeights = {
            exploitability: 0.3,
            impact: 0.3,
            dataSensitivity: 0.2,
            reproducibility: 0.15,
            modelCompliance: 0.15,
        };

        expect(() => new ALVSSEngine(badWeights)).toThrow(/must sum to 1.0/);
    });

    it('handles empty scoreBatch safely', () => {
        const result = engine.scoreBatch([]);
        expect(result.individual).toEqual([]);
        expect(result.aggregate).toBe(0);
        expect(result.aggregateSeverity).toBe(SeverityLevel.Info);
    });

    it('calculates aggregate risk score properly using scoreBatch', () => {
        const findings = [
            baseFinding({
                id: '1',
                severity: SeverityLevel.Critical,
                confidence: 1.0,
            }),
            baseFinding({
                id: '2',
                severity: SeverityLevel.High,
                confidence: 0.9,
                attempts: 2,
                successes: 2,
            }),
        ];

        const batchResult = engine.scoreBatch(findings);
        expect(batchResult.individual.length).toBe(2);
        expect(batchResult.aggregate).toBeGreaterThanOrEqual(8.0);
        expect(batchResult.aggregateSeverity).toBe(SeverityLevel.Critical);
    });

    it('boosts aggregate score when multiple severe findings exist', () => {
        const findings = [
            baseFinding({ id: '1', severity: SeverityLevel.Critical, confidence: 1.0 }),
            baseFinding({ id: '2', severity: SeverityLevel.Critical, confidence: 1.0 }),
            baseFinding({ id: '3', severity: SeverityLevel.High, confidence: 1.0 }),
        ];

        const result = engine.scoreBatch(findings);
        const maxIndividual = Math.max(...result.individual.map((s) => s.score));

        expect(result.aggregate).toBeGreaterThan(maxIndividual);
        expect(result.aggregate).toBeLessThanOrEqual(10);
    });

    it('computes category scores as per-category maxima', () => {
        const findings = [
            baseFinding({
                id: '1',
                category: AttackCategory.PromptInjection,
                severity: SeverityLevel.High,
                confidence: 0.8,
            }),
            baseFinding({
                id: '2',
                category: AttackCategory.PromptInjection,
                severity: SeverityLevel.Critical,
                confidence: 1.0,
            }),
            baseFinding({
                id: '3',
                category: AttackCategory.DataLeakage,
                severity: SeverityLevel.Low,
                confidence: 0.4,
            }),
        ];

        const categoryScores = computeCategoryScores(findings, engine);

        expect(categoryScores[AttackCategory.PromptInjection]).toBeGreaterThanOrEqual(
            categoryScores[AttackCategory.DataLeakage],
        );
        expect(Object.keys(categoryScores).sort()).toEqual(
            [AttackCategory.DataLeakage, AttackCategory.PromptInjection].sort(),
        );
    });

    it('returns empty category scores for empty input', () => {
        expect(computeCategoryScores([], engine)).toEqual({});
    });
});
