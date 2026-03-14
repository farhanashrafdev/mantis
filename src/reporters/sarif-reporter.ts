/**
 * mantis — SARIF Reporter
 *
 * Outputs scan results in SARIF v2.1.0 (Static Analysis Results
 * Interchange Format). This format is supported by:
 *   - GitHub Code Scanning (upload as code scanning alert)
 *   - Azure DevOps
 *   - VS Code SARIF Viewer
 *   - Various SAST/DAST platforms
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type {
    ScanReport,
    Finding,
    Reporter} from '../types/types.js';
import {
    SeverityLevel,
    OutputFormat,
} from '../types/types.js';

/** SARIF severity level mapping */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

function toSarifLevel(severity: SeverityLevel): SarifLevel {
    switch (severity) {
        case SeverityLevel.Critical:
        case SeverityLevel.High:
            return 'error';
        case SeverityLevel.Medium:
            return 'warning';
        case SeverityLevel.Low:
            return 'note';
        case SeverityLevel.Info:
            return 'none';
        default:
            return 'none';
    }
}

/** SARIF security severity mapping (for GitHub — must be numeric CVSS-style) */
function toSecuritySeverity(severity: SeverityLevel): string {
    switch (severity) {
        case SeverityLevel.Critical: return '9.0';
        case SeverityLevel.High: return '7.0';
        case SeverityLevel.Medium: return '4.0';
        case SeverityLevel.Low: return '1.0';
        case SeverityLevel.Info: return '0.0';
        default: return '0.0';
    }
}

/** Rule ID from finding */
function toRuleId(finding: Finding): string {
    return finding.pluginId.replace(/\//g, '-');
}

/** SARIF Result interface */
interface SarifResult {
    ruleId: string;
    level: SarifLevel;
    message: { text: string };
    properties: Record<string, unknown>;
    locations?: unknown[];
}

/** SARIF Rule interface */
interface SarifRule {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    helpUri?: string;
    properties: Record<string, unknown>;
}

/**
 * SARIFReporter — output scan report as SARIF v2.1.0.
 */
export class SARIFReporter implements Reporter {
    name = 'sarif';
    format: OutputFormat = OutputFormat.SARIF;

    generate(report: ScanReport): string {
        const sarif = this.buildSarif(report);
        return JSON.stringify(sarif, null, 2);
    }

    async writeToFile(report: ScanReport, outputPath: string): Promise<void> {
        const { writeFile } = await import('node:fs/promises');
        const content = await this.generate(report);
        await writeFile(outputPath, content, 'utf-8');
    }

    private buildSarif(report: ScanReport): Record<string, unknown> {
        // Collect unique rules from findings
        const rulesMap = new Map<string, SarifRule>();
        const results: SarifResult[] = [];

        for (const finding of report.findings) {
            const ruleId = toRuleId(finding);

            // Add rule if not seen
            if (!rulesMap.has(ruleId)) {
                rulesMap.set(ruleId, {
                    id: ruleId,
                    name: finding.title.split(':')[0].trim(),
                    shortDescription: {
                        text: finding.title,
                    },
                    fullDescription: {
                        text: finding.description,
                    },
                    helpUri: finding.cwe
                        ? `https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`
                        : undefined,
                    properties: {
                        'security-severity': toSecuritySeverity(finding.severity),
                        category: finding.category,
                        tags: ['security', 'ai-security', finding.category],
                    },
                });
            }

            // Build result
            const result: SarifResult = {
                ruleId,
                level: toSarifLevel(finding.severity),
                message: {
                    text: this.buildResultMessage(finding),
                },
                properties: {
                    'mantis-score': finding.riskScore,
                    'mantis-confidence': finding.confidence,
                    'mantis-category': finding.category,
                    'mantis-reproducible': finding.reproducible,
                },
            };

            // Location pointing to the target URL
            result.locations = [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: report.meta.targetUrl,
                            uriBaseId: 'TARGET',
                        },
                    },
                    logicalLocations: [
                        {
                            name: finding.pluginId,
                            kind: 'module',
                        },
                    ],
                },
            ];

            results.push(result);
        }

        return {
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            version: '2.1.0',
            runs: [
                {
                    tool: {
                        driver: {
                            name: 'mantis',
                            fullName: 'mantis — AI Red Team Toolkit',
                            version: report.meta.mantisVersion,
                            semanticVersion: report.meta.mantisVersion,
                            informationUri: 'https://github.com/farhanashrafdev/mantis',
                            rules: Array.from(rulesMap.values()),
                            properties: {
                                'scan-id': report.meta.scanId,
                                'overall-risk-score': report.summary.overallRiskScore,
                                'overall-severity': report.summary.overallSeverity,
                            },
                        },
                    },
                    results,
                    invocations: [
                        {
                            executionSuccessful: true,
                            startTimeUtc: report.meta.startedAt,
                            endTimeUtc: new Date(
                                new Date(report.meta.startedAt).getTime() +
                                report.meta.durationMs,
                            ).toISOString(),
                            properties: {
                                'plugins-executed': report.meta.pluginsExecuted,
                                'total-prompts-sent': report.meta.totalPromptsSent,
                            },
                        },
                    ],
                    properties: {
                        'category-scores': report.summary.categoryScores,
                    },
                },
            ],
        };
    }

    /** Build a detailed message for a SARIF result */
    private buildResultMessage(finding: Finding): string {
        const parts = [
            `**${finding.title}**`,
            '',
            finding.description,
            '',
            `Risk Score: ${finding.riskScore}/10 | Confidence: ${(finding.confidence * 100).toFixed(0)}%`,
            `Reproducible: ${finding.reproducible ? 'Yes' : 'No'}`,
        ];

        if (finding.evidence) {
            parts.push('', `Evidence: ${finding.evidence.substring(0, 300)}`);
        }

        if (finding.remediation) {
            parts.push('', `Remediation: ${finding.remediation}`);
        }

        if (finding.cwe) {
            parts.push('', `CWE: ${finding.cwe}`);
        }

        return parts.join('\n');
    }
}
