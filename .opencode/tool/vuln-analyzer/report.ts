/**
 * JSON Report Generator Module
 * Requirements: 8.1, 8.2, 8.3
 * 
 * Generates structured JSON reports for vulnerability findings.
 */

import { writeFileSync, mkdirSync, existsSync } from "fs"
import { join, basename } from "path"
import type {
  VulnerabilityFinding,
  BinaryReport,
  ReportStatistics,
  SeverityStats,
  TypeStats,
  Severity,
  VulnerabilityType
} from "./types"

/**
 * Generate a unique finding ID
 */
export function generateFindingId(
  binaryPath: string,
  functionAddress: string,
  sinkFunction: string
): string {
  const binaryName = basename(binaryPath).replace(/[^a-zA-Z0-9]/g, "_")
  const timestamp = Date.now().toString(36)
  const addressShort = functionAddress.replace("0x", "").slice(-8)
  return `${binaryName}_${addressShort}_${sinkFunction}_${timestamp}`
}

/**
 * Generate a unique report filename
 * 
 * Property 11: Report Filename Uniqueness
 * For any two reports generated in the same analysis run, their filenames SHALL be unique.
 */
export function generateReportFilename(binaryPath: string): string {
  const binaryName = basename(binaryPath).replace(/[^a-zA-Z0-9.-]/g, "_")
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
  const random = Math.random().toString(36).substring(2, 8)
  return `vuln_report_${binaryName}_${timestamp}_${random}.json`
}

/**
 * Initialize empty severity stats
 */
export function createEmptySeverityStats(): SeverityStats {
  return {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  }
}

/**
 * Initialize empty type stats
 */
export function createEmptyTypeStats(): TypeStats {
  return {
    command_injection: 0,
    buffer_overflow: 0,
    format_string: 0,
    heap_vulnerability: 0
  }
}

/**
 * Calculate statistics from findings
 */
export function calculateStatistics(
  findings: VulnerabilityFinding[],
  totalSinksAnalyzed: number
): ReportStatistics {
  const bySeverity = createEmptySeverityStats()
  const byType = createEmptyTypeStats()

  for (const finding of findings) {
    // Count by severity
    if (finding.severity in bySeverity) {
      bySeverity[finding.severity as Severity]++
    }

    // Count by type
    if (finding.vulnerability_type in byType) {
      byType[finding.vulnerability_type as VulnerabilityType]++
    }
  }

  return {
    total_sinks_analyzed: totalSinksAnalyzed,
    total_findings: findings.length,
    by_severity: bySeverity,
    by_type: byType
  }
}

/**
 * Create a BinaryReport from findings
 * 
 * Property 10: Report Field Completeness
 * For any generated vulnerability report, all required fields SHALL be present.
 */
export function createBinaryReport(
  binaryPath: string,
  findings: VulnerabilityFinding[],
  totalSinksAnalyzed: number,
  idaVersion: string = "unknown"
): BinaryReport {
  return {
    binary_path: binaryPath,
    analysis_timestamp: new Date().toISOString(),
    ida_version: idaVersion,
    findings,
    statistics: calculateStatistics(findings, totalSinksAnalyzed)
  }
}

/**
 * Validate that a finding has all required fields
 */
export function validateFinding(finding: VulnerabilityFinding): boolean {
  const requiredFields: (keyof VulnerabilityFinding)[] = [
    "id",
    "binary_path",
    "function_name",
    "function_address",
    "call_address",
    "vulnerability_type",
    "cwe_id",
    "severity",
    "confidence",
    "sink_function",
    "pseudocode",
    "argument_analysis",
    "call_chain",
    "exploitability"
  ]

  for (const field of requiredFields) {
    if (finding[field] === undefined || finding[field] === null) {
      return false
    }
  }

  // Validate argument_analysis sub-fields
  if (!finding.argument_analysis ||
      finding.argument_analysis.argument_index === undefined ||
      !finding.argument_analysis.source ||
      !finding.argument_analysis.controllability) {
    return false
  }

  return true
}

/**
 * Serialize report to JSON string
 */
export function serializeReport(report: BinaryReport): string {
  return JSON.stringify(report, null, 2)
}

/**
 * Save report to file
 * Requirement 8.3
 */
export function saveReport(
  report: BinaryReport,
  outputDir: string,
  filename?: string
): string {
  // Ensure output directory exists
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true })
  }

  // Generate filename if not provided
  const reportFilename = filename || generateReportFilename(report.binary_path)
  const outputPath = join(outputDir, reportFilename)

  // Write report
  const jsonContent = serializeReport(report)
  writeFileSync(outputPath, jsonContent, "utf-8")

  return outputPath
}

/**
 * Create an empty report for binaries with no findings
 * Requirement 8.4
 */
export function createEmptyReport(
  binaryPath: string,
  totalSinksAnalyzed: number = 0,
  idaVersion: string = "unknown"
): BinaryReport {
  return createBinaryReport(binaryPath, [], totalSinksAnalyzed, idaVersion)
}

/**
 * Create a finding from analysis results
 */
export function createFinding(params: {
  binaryPath: string
  functionName: string
  functionAddress: string
  callAddress: string
  vulnerabilityType: VulnerabilityType
  cweId: string
  severity: Severity
  confidence: "HIGH" | "MEDIUM" | "LOW"
  sinkFunction: string
  pseudocode: string
  argumentIndex: number
  argumentSource: string
  controllability: "FULL" | "PARTIAL" | "NONE"
  callChain: string[]
  exploitability: string
}): VulnerabilityFinding {
  return {
    id: generateFindingId(params.binaryPath, params.functionAddress, params.sinkFunction),
    binary_path: params.binaryPath,
    function_name: params.functionName,
    function_address: params.functionAddress,
    call_address: params.callAddress,
    vulnerability_type: params.vulnerabilityType,
    cwe_id: params.cweId,
    severity: params.severity,
    confidence: params.confidence,
    sink_function: params.sinkFunction,
    pseudocode: params.pseudocode,
    argument_analysis: {
      argument_index: params.argumentIndex,
      source: params.argumentSource,
      controllability: params.controllability
    },
    call_chain: params.callChain,
    exploitability: params.exploitability
  }
}
