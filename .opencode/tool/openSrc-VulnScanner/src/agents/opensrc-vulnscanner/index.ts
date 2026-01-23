/**
 * OpenSrc-VulnScanner - Main orchestrator agent
 * 
 * Responsibilities:
 * - Discover all remote-accessible endpoints in codebase
 * - Calculate priority scores and sort endpoints
 * - Dispatch analysis tasks to EndpointAnalyzer agents
 * - Coordinate VulnVerifier for secondary verification
 * - Aggregate all analysis results
 * - Generate SARIF format reports
 */

import type {
  OpenSrcVulnScanner,
  ScanOptions,
  ScanResult,
  Endpoint,
  AggregatedFindings,
  SARIFReport,
} from '../../types/index.js';
import type { AnalysisResult } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';
import { discoverEndpoints as discoverEndpointsImpl } from './endpoint-discovery.js';
import { enrichEndpointsWithAuth } from './auth-detection.js';
import { calculatePriority, calculateAndSortPriorities, getPriorityStatistics } from './priority-scoring.js';
import { dispatchAnalysisTasks } from './task-dispatcher.js';
import { aggregateResults } from './result-aggregator.js';
import { generateSARIFReport } from './sarif-generator.js';

const logger = createLogger('OpenSrc-VulnScanner');

export class OpenSrcVulnScannerImpl implements OpenSrcVulnScanner {
  async scanCodebase(options: ScanOptions): Promise<ScanResult> {
    logger.info('Starting codebase scan', { codebasePath: options.codebasePath });
    
    const startTime = Date.now();

    try {
      // Step 1: Discover endpoints
      let endpoints = await this.discoverEndpoints(options.codebasePath);
      logger.info(`Discovered ${endpoints.length} endpoints`);

      // Step 2: Detect authentication mechanisms
      endpoints = await enrichEndpointsWithAuth(endpoints);
      const authCount = endpoints.filter(e => e.requiresAuth).length;
      logger.info(`Found ${authCount} authenticated endpoints`);

      // Step 3: Calculate priorities and sort
      endpoints = calculateAndSortPriorities(endpoints);
      const priorityStats = getPriorityStatistics(endpoints);
      logger.info('Priority statistics', priorityStats);

      // Step 4: Filter to top N if specified
      if (options.topN && options.topN > 0) {
        endpoints = endpoints.slice(0, options.topN);
        logger.info(`Filtered to top ${options.topN} priority endpoints`);
      }

      // Step 5: Dispatch analysis tasks
      const analysisResults = await this.dispatchAnalysis(
        endpoints,
        options.concurrency || 5
      );
      logger.info(`Analysis completed`, {
        totalResults: analysisResults.length,
      });

      // Step 6: Aggregate results and verify findings
      const aggregatedFindings = await this.aggregateResults(analysisResults, {
        includeLowConfidence: options.includeLowConfidence,
        verifyFindings: true,
      });
      logger.info(`Results aggregated`, {
        totalFindings: aggregatedFindings.findings.length,
      });

      // Step 7: Generate SARIF report
      const sarifReport = await this.generateSARIF(aggregatedFindings, {
        outputDir: options.outputDir,
        codebasePath: options.codebasePath,
      });
      logger.info(`SARIF report generated`, {
        path: sarifReport.filePath,
      });

      const executionTime = Date.now() - startTime;

      return {
        sarifReportPath: sarifReport.filePath,
        summary: aggregatedFindings.statistics,
        executionTime,
        errors: analysisResults
          .filter(r => r.errors && r.errors.length > 0)
          .flatMap(r => r.errors || []),
      };
    } catch (error) {
      logger.error('Scan failed', error as Error);
      throw error;
    }
  }

  async discoverEndpoints(codebasePath: string): Promise<Endpoint[]> {
    logger.info('Discovering endpoints', { codebasePath });
    return await discoverEndpointsImpl(codebasePath);
  }

  calculatePriority(endpoint: Endpoint): number {
    return calculatePriority(endpoint);
  }

  async dispatchAnalysis(
    endpoints: Endpoint[],
    concurrency: number
  ): Promise<AnalysisResult[]> {
    logger.info('Dispatching analysis tasks', {
      endpointCount: endpoints.length,
      concurrency,
    });
    
    return await dispatchAnalysisTasks(endpoints, {
      concurrency,
      onProgress: (completed, total) => {
        logger.info(`Analysis progress: ${completed}/${total}`);
      },
    });
  }

  async aggregateResults(
    results: AnalysisResult[],
    options?: { includeLowConfidence?: boolean; verifyFindings?: boolean }
  ): Promise<AggregatedFindings> {
    logger.info('Aggregating results', { resultCount: results.length });
    
    return await aggregateResults(results, options);
  }

  async generateSARIF(
    findings: AggregatedFindings,
    options: { outputDir: string; codebasePath: string }
  ): Promise<{ report: SARIFReport; filePath: string }> {
    logger.info('Generating SARIF report', {
      findingCount: findings.findings.length,
    });
    
    return await generateSARIFReport(findings, options);
  }
}
