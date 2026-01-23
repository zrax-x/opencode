/**
 * OpenSrc-Coordinator - Main orchestrator agent
 * 
 * Responsibilities:
 * - Coordinate the entire vulnerability analysis pipeline
 * - Dispatch tasks to specialized agents (endpoint-discoverer, endpoint-analyzer, vuln-verifier, opensrc-reporter)
 * - Aggregate results from all agents
 * - Manage analysis workflow phases
 * 
 * This is the PURE COORDINATOR - it does NOT perform any analysis itself.
 */

import type {
    ScanOptions,
    ScanResult,
    Endpoint,
    AggregatedFindings,
    SARIFReport,
    AnalysisResult,
} from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';
import { EndpointDiscovererImpl } from '../endpoint-discoverer/index.js';
import { dispatchAnalysisTasks } from './task-dispatcher.js';
import { OpenSrcReporterImpl } from '../opensrc-reporter/index.js';

const logger = createLogger('OpenSrc-Coordinator');

export interface CoordinatorPhase {
    name: string;
    status: 'pending' | 'in_progress' | 'complete' | 'failed';
    startTime?: Date;
    endTime?: Date;
    result?: any;
}

export interface CoordinatorProgress {
    taskId: string;
    phases: {
        discovery: CoordinatorPhase;
        analysis: CoordinatorPhase;
        verification: CoordinatorPhase;
        reporting: CoordinatorPhase;
    };
}

export class OpenSrcCoordinatorImpl {
    private discoverer = new EndpointDiscovererImpl();
    private reporter = new OpenSrcReporterImpl();

    async coordinateAnalysis(options: ScanOptions): Promise<ScanResult> {
        logger.info('[COORD] Task received', { codebasePath: options.codebasePath });

        const startTime = Date.now();
        const taskId = `scan_${Date.now()}`;

        // Initialize progress tracking
        await this.reporter.initProgress(taskId, options.codebasePath);

        try {
            // ========== Phase 1: Discovery ==========
            logger.info('[COORD] Phase 1: Dispatching endpoint-discoverer');
            await this.reporter.updatePhase(taskId, 'discovery', 'in_progress');

            let endpoints = await this.discoverer.discoverEndpoints(options.codebasePath);
            logger.info(`[COORD] Discovery complete: ${endpoints.length} endpoints found`);

            await this.reporter.updatePhase(taskId, 'discovery', 'complete', {
                endpointCount: endpoints.length,
            });

            // Apply topN filter if specified
            if (options.topN && options.topN > 0) {
                endpoints = endpoints.slice(0, options.topN);
                logger.info(`[COORD] Filtered to top ${options.topN} endpoints`);
            }

            // ========== Phase 2: Analysis ==========
            logger.info(`[COORD] Phase 2: Dispatching endpoint-analyzer (${endpoints.length} tasks)`);
            await this.reporter.updatePhase(taskId, 'analysis', 'in_progress');

            const analysisResults = await dispatchAnalysisTasks(endpoints, {
                concurrency: options.concurrency || 5,
                onProgress: (completed, total) => {
                    logger.info(`[COORD] Analysis progress: ${completed}/${total}`);
                },
            });

            const totalFindings = analysisResults.reduce((sum, r) => sum + r.findings.length, 0);
            logger.info(`[COORD] Analysis complete: ${totalFindings} findings from ${endpoints.length} endpoints`);

            await this.reporter.updatePhase(taskId, 'analysis', 'complete', {
                analyzedEndpoints: analysisResults.length,
                findingsCount: totalFindings,
            });

            // ========== Phase 3: Verification (integrated in reporter) ==========
            logger.info(`[COORD] Phase 3: Dispatching vuln-verifier (${totalFindings} findings)`);
            await this.reporter.updatePhase(taskId, 'verification', 'in_progress');

            const aggregatedFindings = await this.reporter.aggregateAndVerify(analysisResults, {
                includeLowConfidence: options.includeLowConfidence,
                verifyFindings: true,
            });

            const confirmedCount = aggregatedFindings.findings.filter(
                f => f.confidence === 'HIGH_CONFIDENCE'
            ).length;
            const uncertainCount = aggregatedFindings.findings.filter(
                f => f.confidence === 'MEDIUM_CONFIDENCE'
            ).length;

            logger.info(`[COORD] Verification complete: ${confirmedCount} CONFIRMED, ${uncertainCount} UNCERTAIN`);

            await this.reporter.updatePhase(taskId, 'verification', 'complete', {
                confirmed: confirmedCount,
                uncertain: uncertainCount,
            });

            // ========== Phase 4: Reporting ==========
            logger.info('[COORD] Phase 4: Dispatching opensrc-reporter');
            await this.reporter.updatePhase(taskId, 'reporting', 'in_progress');

            const reportResult = await this.reporter.generateReports(aggregatedFindings, {
                outputDir: options.outputDir,
                codebasePath: options.codebasePath,
            });

            logger.info(`[COORD] Report generated: ${reportResult.sarifPath}`);

            await this.reporter.updatePhase(taskId, 'reporting', 'complete', {
                sarifPath: reportResult.sarifPath,
            });

            const executionTime = Date.now() - startTime;

            logger.info(`[COORD] COMPLETE: ${confirmedCount} confirmed vulnerabilities found`, {
                executionTime: `${(executionTime / 1000).toFixed(1)}s`,
            });

            return {
                sarifReportPath: reportResult.sarifPath,
                summary: aggregatedFindings.statistics,
                executionTime,
                errors: analysisResults
                    .filter(r => r.errors && r.errors.length > 0)
                    .flatMap(r => r.errors || []),
            };
        } catch (error) {
            logger.error('[COORD] Coordination failed', error as Error);
            throw error;
        }
    }
}
