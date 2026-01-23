/**
 * Result Aggregator - Collects and filters analysis results
 * 
 * Responsibilities:
 * - Collect findings from all EndpointAnalyzer results
 * - Apply confidence filtering
 * - Calculate statistics
 * - Prepare data for SARIF generation
 */

import type {
  AnalysisResult,
  AggregatedFindings,
  FindingWithConfidence,
  Confidence,
  Severity,
  VulnerabilityType,
} from '../../types/index.js';
import { VulnVerifierImpl } from '../vuln-verifier/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('ResultAggregator');

export interface AggregationOptions {
  includeLowConfidence?: boolean;
  verifyFindings?: boolean;
}

export async function aggregateResults(
  results: AnalysisResult[],
  options: AggregationOptions = {}
): Promise<AggregatedFindings> {
  logger.info(`Aggregating results`, {
    resultCount: results.length,
    verifyFindings: options.verifyFindings,
  });

  const verifier = options.verifyFindings ? new VulnVerifierImpl() : null;
  const findingsWithConfidence: FindingWithConfidence[] = [];

  // Process each result
  for (const result of results) {
    for (const finding of result.findings) {
      let confidence: Confidence = 'MEDIUM_CONFIDENCE';

      // Verify finding if requested
      if (verifier) {
        try {
          const verification = await verifier.verifyVulnerability(finding);

          // Map verification confidence to our confidence levels
          confidence = mapVerificationToConfidence(verification.confidence);

          // Skip rejected findings
          if (verification.confidence === 'REJECTED') {
            logger.debug(`Rejected finding`, {
              endpoint: result.endpoint.routePattern,
              type: finding.vulnerabilityType,
            });
            continue;
          }
        } catch (error) {
          logger.warn(`Verification failed, using default confidence`, {
            error: error as Error,
          });
        }
      }

      findingsWithConfidence.push({
        ...finding,
        confidence,
      });
    }
  }

  // Filter by confidence if requested
  let filteredFindings = findingsWithConfidence;
  if (!options.includeLowConfidence) {
    filteredFindings = findingsWithConfidence.filter(
      f => f.confidence !== 'LOW_CONFIDENCE'
    );
    logger.info(`Filtered out low confidence findings`, {
      before: findingsWithConfidence.length,
      after: filteredFindings.length,
    });
  }

  // Calculate statistics
  const statistics = calculateStatistics(results, filteredFindings);

  logger.info(`Aggregation completed`, {
    totalFindings: filteredFindings.length,
    bySeverity: statistics.bySeverity,
  });

  return {
    findings: filteredFindings,
    statistics,
  };
}

function mapVerificationToConfidence(
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

function calculateStatistics(
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
