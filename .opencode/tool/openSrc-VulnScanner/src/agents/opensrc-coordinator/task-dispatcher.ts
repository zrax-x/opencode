/**
 * Task Dispatcher - Manages parallel analysis of endpoints
 * 
 * Responsibilities:
 * - Dispatch analysis tasks to EndpointAnalyzer agents
 * - Control concurrency (default 5 concurrent tasks)
 * - Track progress and provide status updates
 * - Handle errors and continue processing
 */

import type { Endpoint, AnalysisResult } from '../../types/index.js';
import { EndpointAnalyzerImpl } from '../endpoint-analyzer/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('TaskDispatcher');

export interface DispatchOptions {
  concurrency?: number;
  onProgress?: (completed: number, total: number) => void;
}

export async function dispatchAnalysisTasks(
  endpoints: Endpoint[],
  options: DispatchOptions = {}
): Promise<AnalysisResult[]> {
  const concurrency = options.concurrency || 5;
  const total = endpoints.length;
  let completed = 0;
  const results: AnalysisResult[] = [];
  const errors: Array<{ endpoint: Endpoint; error: Error }> = [];

  logger.info(`Starting analysis dispatch`, { total, concurrency });

  // Create analyzer instance
  const analyzer = new EndpointAnalyzerImpl();

  // Process endpoints in batches
  for (let i = 0; i < endpoints.length; i += concurrency) {
    const batch = endpoints.slice(i, i + concurrency);
    
    const batchPromises = batch.map(async (endpoint) => {
      try {
        const result = await analyzer.analyzeEndpoint({ endpoint });
        completed++;
        
        if (options.onProgress) {
          options.onProgress(completed, total);
        }
        
        logger.info(`Analyzed endpoint ${completed}/${total}`, {
          endpoint: endpoint.routePattern,
          findings: result.findings.length,
        });
        
        return result;
      } catch (error) {
        completed++;
        logger.error(`Failed to analyze endpoint`, error as Error);
        
        errors.push({ endpoint, error: error as Error });
        
        // Return empty result on error
        return {
          endpoint,
          findings: [],
          authInfo: { requiresAuth: endpoint.requiresAuth },
          analysisTime: 0,
          errors: [(error as Error).message],
        } as AnalysisResult;
      }
    });

    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
  }

  logger.info(`Analysis dispatch completed`, {
    total,
    successful: results.filter(r => !r.errors || r.errors.length === 0).length,
    failed: errors.length,
  });

  return results;
}
