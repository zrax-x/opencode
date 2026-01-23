/**
 * SARIF Report Generator - Generates SARIF 2.1.0 format reports
 * 
 * Responsibilities:
 * - Generate SARIF 2.1.0 compliant reports
 * - Organize findings by endpoint
 * - Include complete metadata (CWE, severity, confidence)
 * - Include data flow paths as code flows
 * - Generate summary statistics
 */

import type {
  AggregatedFindings,
  SARIFReport,
  SARIFRun,
  SARIFResult,
  SARIFLocation,
  SARIFCodeFlow,
  FindingWithConfidence,
  Severity,
} from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';
import { promises as fs } from 'fs';
import path from 'path';

const logger = createLogger('SARIFGenerator');

export interface SARIFGenerationOptions {
  outputDir: string;
  codebasePath: string;
}

export async function generateSARIFReport(
  findings: AggregatedFindings,
  options: SARIFGenerationOptions
): Promise<{ report: SARIFReport; filePath: string }> {
  logger.info(`Generating SARIF report`, {
    findingCount: findings.findings.length,
  });

  const startTime = new Date().toISOString();
  
  const report: SARIFReport = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'OpenSrc-VulnScanner',
            version: '1.0.0',
            informationUri: 'https://github.com/opencode/opensrc-vulnscanner',
          },
        },
        results: findings.findings.map(finding => convertFindingToSARIF(finding, options.codebasePath)),
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

  // Write report to file
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `vulnerability-report-${timestamp}.sarif`;
  const filePath = path.join(options.outputDir, fileName);

  await fs.mkdir(options.outputDir, { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(report, null, 2), 'utf-8');

  logger.info(`SARIF report generated`, { filePath });

  return { report, filePath };
}

function convertFindingToSARIF(
  finding: FindingWithConfidence,
  codebasePath: string
): SARIFResult {
  const level = mapSeverityToSARIFLevel(finding.severity);
  
  // Create main location
  const mainLocation: SARIFLocation = {
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
  };

  // Create code flow from data flow path
  const codeFlows: SARIFCodeFlow[] = [];
  if (finding.dataFlowPath && finding.dataFlowPath.steps.length > 0) {
    codeFlows.push({
      threadFlows: [
        {
          locations: finding.dataFlowPath.steps.map(step => ({
            location: {
              physicalLocation: {
                artifactLocation: {
                  uri: path.relative(codebasePath, step.location.filePath),
                },
                region: {
                  startLine: step.location.lineNumber,
                  startColumn: step.location.columnNumber,
                },
              },
            },
            state: {
              operation: step.operation || step.type,
              variable: step.variable || '',
            },
          })),
        },
      ],
    });
  }

  return {
    ruleId: `${finding.vulnerabilityType}_CWE${finding.cweId}`,
    level,
    message: {
      text: `${finding.vulnerabilityType}: ${getVulnerabilityDescription(finding.vulnerabilityType)} (Confidence: ${finding.confidence})`,
    },
    locations: [mainLocation],
    codeFlows: codeFlows.length > 0 ? codeFlows : undefined,
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      cweId: finding.cweId,
      vulnerabilityType: finding.vulnerabilityType,
      functionName: finding.location.functionName,
    },
  };
}

function mapSeverityToSARIFLevel(severity: Severity): 'error' | 'warning' | 'note' {
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

function getVulnerabilityDescription(type: string): string {
  const descriptions: Record<string, string> = {
    RCE: 'Remote Code Execution vulnerability detected',
    COMMAND_INJECTION: 'Command Injection vulnerability detected',
    AUTH_BYPASS: 'Authentication Bypass vulnerability detected',
    ARBITRARY_FILE_READ: 'Arbitrary File Read vulnerability detected',
    PATH_TRAVERSAL: 'Path Traversal vulnerability detected',
  };
  return descriptions[type] || 'Vulnerability detected';
}
