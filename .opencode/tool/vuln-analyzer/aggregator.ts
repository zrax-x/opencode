/**
 * Report Aggregation and Deduplication Module
 * Requirements: 9.1, 9.2, 9.3, 9.4
 * 
 * Collects individual JSON reports, deduplicates findings from shared libraries,
 * and generates aggregated statistics.
 */

import { readdirSync, readFileSync } from "fs"
import { join } from "path"
import type {
  BinaryReport,
  VulnerabilityFinding,
  AggregatedFinding,
  AggregatedReport,
  ReportStatistics,
  Severity,
  VulnerabilityType
} from "./types"
import { createEmptySeverityStats, createEmptyTypeStats } from "./report"

/**
 * Generate a deduplication key for a finding
 * Used to identify duplicate vulnerabilities in shared libraries
 */
export function generateDeduplicationKey(finding: VulnerabilityFinding): string {
  // Key based on function address and sink function
  // This identifies the same vulnerability across different binaries
  return `${finding.function_address}_${finding.sink_function}_${finding.vulnerability_type}`
}

/**
 * Check if two findings are duplicates
 * 
 * Property 12: Duplicate Detection Correctness
 * For any two vulnerability findings with the same function_address and sink_function
 * in a shared library, they SHALL be identified as duplicates.
 */
export function areDuplicates(
  finding1: VulnerabilityFinding,
  finding2: VulnerabilityFinding
): boolean {
  return (
    finding1.function_address === finding2.function_address &&
    finding1.sink_function === finding2.sink_function &&
    finding1.vulnerability_type === finding2.vulnerability_type
  )
}

/**
 * Load a single JSON report from file
 */
export function loadReport(filePath: string): BinaryReport | null {
  try {
    const content = readFileSync(filePath, "utf-8")
    return JSON.parse(content) as BinaryReport
  } catch {
    return null
  }
}

/**
 * Collect all JSON reports from a directory
 * Requirement 9.1
 */
export function collectReports(outputDir: string): BinaryReport[] {
  const reports: BinaryReport[] = []

  try {
    const files = readdirSync(outputDir)
    const jsonFiles = files.filter(f => f.endsWith(".json") && f.startsWith("vuln_report_"))

    for (const file of jsonFiles) {
      const report = loadReport(join(outputDir, file))
      if (report) {
        reports.push(report)
      }
    }
  } catch {
    // Directory doesn't exist or can't be read
  }

  return reports
}

/**
 * Convert a VulnerabilityFinding to an AggregatedFinding
 */
function toAggregatedFinding(
  finding: VulnerabilityFinding,
  affectedBinaries: string[]
): AggregatedFinding {
  return {
    ...finding,
    affected_binaries: affectedBinaries
  }
}

/**
 * Deduplicate findings from multiple reports
 * 
 * Property 13: Duplicate Merge Correctness
 * For any set of duplicate findings, the merged entry SHALL contain
 * references to all affected binaries from the original findings.
 * 
 * Requirements: 9.2, 9.3
 */
export function deduplicateFindings(reports: BinaryReport[]): AggregatedFinding[] {
  // Map from deduplication key to aggregated finding
  const findingMap = new Map<string, AggregatedFinding>()

  for (const report of reports) {
    for (const finding of report.findings) {
      const key = generateDeduplicationKey(finding)

      if (findingMap.has(key)) {
        // Duplicate found - add binary to affected list
        const existing = findingMap.get(key)!
        if (!existing.affected_binaries.includes(finding.binary_path)) {
          existing.affected_binaries.push(finding.binary_path)
        }
      } else {
        // New finding
        findingMap.set(key, toAggregatedFinding(finding, [finding.binary_path]))
      }
    }
  }

  return Array.from(findingMap.values())
}

/**
 * Calculate aggregated statistics
 * 
 * Property 14: Statistics Accuracy
 * For any aggregated report, the statistics SHALL accurately reflect
 * the actual findings in the report.
 * 
 * Requirement 9.4
 */
export function calculateAggregatedStatistics(
  findings: AggregatedFinding[],
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
 * Aggregate multiple reports into a single report
 */
export function aggregateReports(reports: BinaryReport[]): AggregatedReport {
  // Deduplicate findings
  const deduplicatedFindings = deduplicateFindings(reports)

  // Calculate total sinks analyzed across all reports
  const totalSinksAnalyzed = reports.reduce(
    (sum, report) => sum + report.statistics.total_sinks_analyzed,
    0
  )

  // Calculate aggregated statistics
  const statistics = calculateAggregatedStatistics(deduplicatedFindings, totalSinksAnalyzed)

  return {
    analysis_timestamp: new Date().toISOString(),
    total_binaries_analyzed: reports.length,
    findings: deduplicatedFindings,
    statistics
  }
}

/**
 * Get summary of duplicates found
 */
export function getDuplicateSummary(
  findings: AggregatedFinding[]
): { total: number; duplicates: number; uniqueVulnerabilities: number } {
  const duplicates = findings.filter(f => f.affected_binaries.length > 1)
  return {
    total: findings.reduce((sum, f) => sum + f.affected_binaries.length, 0),
    duplicates: duplicates.length,
    uniqueVulnerabilities: findings.length
  }
}

/**
 * Sort findings by severity (most severe first)
 */
export function sortBySeverity(findings: AggregatedFinding[]): AggregatedFinding[] {
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4
  }

  return [...findings].sort((a, b) => {
    return severityOrder[a.severity] - severityOrder[b.severity]
  })
}

/**
 * Filter findings by minimum severity
 */
export function filterBySeverity(
  findings: AggregatedFinding[],
  minSeverity: Severity
): AggregatedFinding[] {
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4
  }

  const minLevel = severityOrder[minSeverity]
  return findings.filter(f => severityOrder[f.severity] <= minLevel)
}
