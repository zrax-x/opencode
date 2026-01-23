/**
 * OpenSrc-Reporter - Report generation agent
 * 
 * Responsibilities:
 * - Track analysis progress across phases
 * - Aggregate and verify findings
 * - Generate SARIF 2.1.0 reports
 * - Output statistics
 * 
 * This agent is called by opensrc-coordinator during Phase 3 and 4.
 */

import type {
    AnalysisResult,
    AggregatedFindings,
    FindingWithConfidence,
    SARIFReport,
    Confidence,
    Severity,
    VulnerabilityType,
} from '../../types/index.js';
import { VulnVerifierImpl } from '../vuln-verifier/index.js';
import { createLogger } from '../../utils/logger.js';
import { promises as fs } from 'fs';
import path from 'path';

const logger = createLogger('OpenSrc-Reporter');

export interface ReportGenerationOptions {
    outputDir: string;
    codebasePath: string;
}

export interface ReportResult {
    sarifPath: string;
    statisticsPath: string;
    progressPath: string;
}

export interface ProgressData {
    taskId: string;
    codebasePath: string;
    startTime: string;
    currentPhase: string;
    phases: Record<string, {
        status: string;
        startTime?: string;
        endTime?: string;
        result?: any;
    }>;
}

export class OpenSrcReporterImpl {
    private progressData: ProgressData | null = null;
    private outputDir: string = '';

    async initProgress(taskId: string, codebasePath: string): Promise<void> {
        this.progressData = {
            taskId,
            codebasePath,
            startTime: new Date().toISOString(),
            currentPhase: 'initializing',
            phases: {
                discovery: { status: 'pending' },
                analysis: { status: 'pending' },
                verification: { status: 'pending' },
                reporting: { status: 'pending' },
            },
        };
        logger.info('[REPORTER] Progress tracking initialized', { taskId });
    }

    async updatePhase(
        taskId: string,
        phase: string,
        status: string,
        result?: any
    ): Promise<void> {
        if (!this.progressData || this.progressData.taskId !== taskId) {
            return;
        }

        const phaseData = this.progressData.phases[phase];
        if (phaseData) {
            phaseData.status = status;
            if (status === 'in_progress') {
                phaseData.startTime = new Date().toISOString();
            } else if (status === 'complete' || status === 'failed') {
                phaseData.endTime = new Date().toISOString();
                phaseData.result = result;
            }
            this.progressData.currentPhase = phase;
        }
    }

    async aggregateAndVerify(
        results: AnalysisResult[],
        options: { includeLowConfidence?: boolean; verifyFindings?: boolean } = {}
    ): Promise<AggregatedFindings> {
        logger.info('[REPORTER] Aggregating and verifying findings', {
            resultCount: results.length,
            verifyFindings: options.verifyFindings,
        });

        const verifier = options.verifyFindings ? new VulnVerifierImpl() : null;
        const findingsWithConfidence: FindingWithConfidence[] = [];

        let verified = 0;
        let rejected = 0;

        for (const result of results) {
            for (const finding of result.findings) {
                let confidence: Confidence = 'MEDIUM_CONFIDENCE';

                if (verifier) {
                    try {
                        const verification = await verifier.verifyVulnerability(finding);
                        confidence = this.mapVerificationToConfidence(verification.confidence);

                        if (verification.confidence === 'REJECTED') {
                            rejected++;
                            logger.debug('[REPORTER] Rejected finding', {
                                endpoint: result.endpoint.routePattern,
                                type: finding.vulnerabilityType,
                            });
                            continue;
                        }
                        verified++;
                    } catch (error) {
                        logger.warn('[REPORTER] Verification failed, using default confidence');
                    }
                }

                findingsWithConfidence.push({
                    ...finding,
                    confidence,
                });
            }
        }

        logger.info(`[REPORTER] Verification: ${verified} processed, ${rejected} rejected`);

        // Filter by confidence if requested
        let filteredFindings = findingsWithConfidence;
        if (!options.includeLowConfidence) {
            filteredFindings = findingsWithConfidence.filter(
                f => f.confidence !== 'LOW_CONFIDENCE'
            );
        }

        const statistics = this.calculateStatistics(results, filteredFindings);

        return {
            findings: filteredFindings,
            statistics,
        };
    }

    async generateReports(
        findings: AggregatedFindings,
        options: ReportGenerationOptions
    ): Promise<ReportResult> {
        this.outputDir = options.outputDir;
        await fs.mkdir(options.outputDir, { recursive: true });

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

        // Generate SARIF report
        const sarifPath = path.join(options.outputDir, `vulnerability_report_${timestamp}.sarif`);
        const sarifReport = this.generateSARIF(findings, options.codebasePath);
        await fs.writeFile(sarifPath, JSON.stringify(sarifReport, null, 2), 'utf-8');
        logger.info('[REPORTER] SARIF report generated', { path: sarifPath });

        // Generate statistics JSON
        const statisticsPath = path.join(options.outputDir, 'statistics.json');
        await fs.writeFile(statisticsPath, JSON.stringify(findings.statistics, null, 2), 'utf-8');

        // Save progress
        const progressPath = path.join(options.outputDir, 'progress.json');
        if (this.progressData) {
            await fs.writeFile(progressPath, JSON.stringify(this.progressData, null, 2), 'utf-8');
        }

        logger.info('[REPORTER] All reports generated', {
            sarifPath,
            statisticsPath,
        });

        return {
            sarifPath,
            statisticsPath,
            progressPath,
        };
    }

    private generateSARIF(findings: AggregatedFindings, codebasePath: string): SARIFReport {
        const startTime = new Date().toISOString();

        return {
            version: '2.1.0',
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            runs: [
                {
                    tool: {
                        driver: {
                            name: 'OpenSrc-VulnScanner',
                            version: '2.0.0',
                            informationUri: 'https://github.com/opencode/opensrc-vulnscanner',
                        },
                    },
                    results: findings.findings.map(finding => this.convertFindingToSARIF(finding, codebasePath)),
                    invocations: [
                        {
                            executionSuccessful: true,
                            startTimeUtc: startTime,
                            endTimeUtc: new Date().toISOString(),
                        },
                    ],
                },
            ],
        };
    }

    private convertFindingToSARIF(finding: FindingWithConfidence, codebasePath: string) {
        const level = this.mapSeverityToSARIFLevel(finding.severity);

        return {
            ruleId: `${finding.vulnerabilityType}_CWE${finding.cweId}`,
            level,
            message: {
                text: `${finding.vulnerabilityType}: ${this.getVulnerabilityDescription(finding.vulnerabilityType)} (Confidence: ${finding.confidence})`,
            },
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: path.relative(codebasePath, finding.location.filePath),
                        },
                        region: {
                            startLine: finding.location.lineNumber,
                            startColumn: finding.location.columnNumber,
                            snippet: {
                                text: finding.codeSnippet,
                            },
                        },
                    },
                },
            ],
            properties: {
                severity: finding.severity,
                confidence: finding.confidence,
                cweId: finding.cweId,
                vulnerabilityType: finding.vulnerabilityType,
                functionName: finding.location.functionName,
            },
        };
    }


    private mapVerificationToConfidence(
        verificationConfidence: 'CONFIRMED' | 'UNCERTAIN' | 'REJECTED'
    ): Confidence {
        switch (verificationConfidence) {
            case 'CONFIRMED':
                return 'HIGH_CONFIDENCE';
            case 'UNCERTAIN':
                return 'MEDIUM_CONFIDENCE';
            case 'REJECTED':
                return 'LOW_CONFIDENCE';
        }
    }

    private mapSeverityToSARIFLevel(severity: Severity): 'error' | 'warning' | 'note' {
        switch (severity) {
            case 'CRITICAL':
            case 'HIGH':
                return 'error';
            case 'MEDIUM':
                return 'warning';
            case 'LOW':
                return 'note';
        }
    }

    private getVulnerabilityDescription(type: string): string {
        const descriptions: Record<string, string> = {
            RCE: 'Remote Code Execution vulnerability detected',
            COMMAND_INJECTION: 'Command Injection vulnerability detected',
            AUTH_BYPASS: 'Authentication Bypass vulnerability detected',
            ARBITRARY_FILE_READ: 'Arbitrary File Read vulnerability detected',
            PATH_TRAVERSAL: 'Path Traversal vulnerability detected',
        };
        return descriptions[type] || 'Vulnerability detected';
    }

    private calculateStatistics(
        results: AnalysisResult[],
        findings: FindingWithConfidence[]
    ) {
        const bySeverity: Record<Severity, number> = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
        };

        const byType: Record<VulnerabilityType, number> = {
            RCE: 0,
            COMMAND_INJECTION: 0,
            AUTH_BYPASS: 0,
            ARBITRARY_FILE_READ: 0,
            PATH_TRAVERSAL: 0,
        };

        const byConfidence: Record<Confidence, number> = {
            HIGH_CONFIDENCE: 0,
            MEDIUM_CONFIDENCE: 0,
            LOW_CONFIDENCE: 0,
        };

        for (const finding of findings) {
            bySeverity[finding.severity]++;
            byType[finding.vulnerabilityType]++;
            byConfidence[finding.confidence]++;
        }

        const analyzedEndpoints = results.filter(
            r => !r.errors || r.errors.length === 0
        ).length;

        return {
            totalEndpoints: results.length,
            analyzedEndpoints,
            totalFindings: findings.length,
            bySeverity,
            byType,
            byConfidence,
        };
    }
}
