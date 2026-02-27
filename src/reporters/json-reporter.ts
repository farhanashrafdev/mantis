/**
 * mantis — JSON Reporter
 *
 * Outputs scan results as structured JSON. Used for:
 *   - CI/CD pipeline integration
 *   - Programmatic consumption
 *   - Format conversion (input to other reporters)
 *   - API responses
 */

import {
    ScanReport,
    Reporter,
    OutputFormat,
} from '../types/types.js';

/**
 * JSONReporter — output scan report as structured JSON.
 */
export class JSONReporter implements Reporter {
    name = 'json';
    format: OutputFormat = OutputFormat.JSON;

    /** Pretty-print the scan report as JSON */
    generate(report: ScanReport): string {
        return JSON.stringify(this.normalizeReport(report), null, 2);
    }

    /** Compact JSON (for API responses) */
    generateCompact(report: ScanReport): string {
        return JSON.stringify(this.normalizeReport(report));
    }

    async writeToFile(report: ScanReport, outputPath: string): Promise<void> {
        const { writeFile } = await import('node:fs/promises');
        const content = this.generate(report);
        await writeFile(outputPath, content, 'utf-8');
    }

    /**
     * Normalize the report for clean JSON output.
     * Ensures all fields are serializable and removes undefined values.
     */
    private normalizeReport(report: ScanReport): Record<string, unknown> {
        return {
            $schema: 'https://github.com/farhanashrafdev/mantis/schemas/report-v1.json',
            version: '1.0',
            meta: {
                scanId: report.meta.scanId,
                targetUrl: report.meta.targetUrl,
                startedAt: report.meta.startedAt,
                completedAt: report.meta.completedAt,
                durationMs: report.meta.durationMs,
                pluginsExecuted: report.meta.pluginsExecuted,
                totalPromptsSent: report.meta.totalPromptsSent,
                mantisVersion: report.meta.mantisVersion,
            },
            summary: {
                overallRiskScore: report.summary.overallRiskScore,
                overallSeverity: report.summary.overallSeverity,
                totalFindings: report.summary.totalFindings,
                criticalCount: report.summary.criticalCount,
                highCount: report.summary.highCount,
                mediumCount: report.summary.mediumCount,
                lowCount: report.summary.lowCount,
                infoCount: report.summary.infoCount,
                categoryScores: report.summary.categoryScores,
            },
            findings: report.findings.map((f) => ({
                id: f.id,
                pluginId: f.pluginId,
                category: f.category,
                title: f.title,
                description: f.description,
                severity: f.severity,
                riskScore: f.riskScore,
                confidence: f.confidence,
                attackPrompt: f.attackPrompt,
                response: f.response,
                evidence: f.evidence ?? null,
                remediation: f.remediation ?? null,
                cwe: f.cwe ?? null,
                timestamp: f.timestamp,
                reproducible: f.reproducible,
                attempts: f.attempts ?? null,
                successes: f.successes ?? null,
            })),
        };
    }
}
