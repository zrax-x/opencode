/**
 * Progress Tracking Module
 * Requirements: 11.1, 11.2, 11.3, 11.4
 * 
 * Tracks and formats progress messages during vulnerability analysis.
 */

import type { ProgressState, ProgressMessage, ReportStatistics } from "./types"

/**
 * Create initial progress state
 * Requirement 11.1
 */
export function createProgressState(totalBinaries: number): ProgressState {
  return {
    total_binaries: totalBinaries,
    current_index: 0,
    current_binary: "",
    start_time: Date.now(),
    findings_per_binary: {}
  }
}

/**
 * Format duration in human-readable format
 */
export function formatDuration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`
  }
  return `${seconds}s`
}

/**
 * Generate start message
 * Requirement 11.1
 * 
 * Property 17: Progress Output Completeness
 * The progress output SHALL include initial total count.
 */
export function formatStartMessage(state: ProgressState): ProgressMessage {
  return {
    type: "start",
    message: `[START] Beginning vulnerability analysis of ${state.total_binaries} binaries`,
    data: {
      total_binaries: state.total_binaries,
      start_time: new Date(state.start_time).toISOString()
    }
  }
}

/**
 * Generate progress message for current binary
 * Requirement 11.2
 * 
 * Property 17: Progress Output Completeness
 * The progress output SHALL include N progress updates (one per binary).
 */
export function formatProgressMessage(
  state: ProgressState,
  binaryName: string
): ProgressMessage {
  const current = state.current_index + 1
  const total = state.total_binaries
  const percentage = Math.round((current / total) * 100)

  return {
    type: "progress",
    message: `[ANALYSIS] Analyzing ${binaryName} (${current}/${total}) - ${percentage}%`,
    data: {
      current_index: current,
      total: total,
      binary_name: binaryName,
      percentage
    }
  }
}

/**
 * Generate completion message for a binary
 * Requirement 11.3
 * 
 * Property 17: Progress Output Completeness
 * The progress output SHALL include N completion summaries.
 */
export function formatCompletionMessage(
  binaryName: string,
  findingsCount: number,
  severityBreakdown: Record<string, number>
): ProgressMessage {
  const severityStr = Object.entries(severityBreakdown)
    .filter(([_, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`)
    .join(", ")

  const summaryStr = severityStr || "no findings"

  return {
    type: "complete",
    message: `[COMPLETE] ${binaryName}: ${findingsCount} findings (${summaryStr})`,
    data: {
      binary_name: binaryName,
      findings_count: findingsCount,
      severity_breakdown: severityBreakdown
    }
  }
}

/**
 * Generate final summary message
 * Requirement 11.4
 * 
 * Property 17: Progress Output Completeness
 * The progress output SHALL include final statistics with execution time.
 */
export function formatSummaryMessage(
  state: ProgressState,
  statistics: ReportStatistics
): ProgressMessage {
  const endTime = Date.now()
  const duration = formatDuration(endTime - state.start_time)

  const severityStr = [
    `CRITICAL: ${statistics.by_severity.CRITICAL}`,
    `HIGH: ${statistics.by_severity.HIGH}`,
    `MEDIUM: ${statistics.by_severity.MEDIUM}`,
    `LOW: ${statistics.by_severity.LOW}`
  ].join(", ")

  return {
    type: "summary",
    message: `[SUMMARY] Analysis complete:
  - Binaries analyzed: ${state.total_binaries}
  - Total findings: ${statistics.total_findings}
  - ${severityStr}
  - Execution time: ${duration}`,
    data: {
      total_binaries: state.total_binaries,
      total_findings: statistics.total_findings,
      by_severity: statistics.by_severity,
      by_type: statistics.by_type,
      execution_time_ms: endTime - state.start_time,
      execution_time_formatted: duration
    }
  }
}

/**
 * Update progress state for next binary
 */
export function advanceProgress(
  state: ProgressState,
  binaryName: string,
  findingsCount: number
): ProgressState {
  return {
    ...state,
    current_index: state.current_index + 1,
    current_binary: binaryName,
    findings_per_binary: {
      ...state.findings_per_binary,
      [binaryName]: findingsCount
    }
  }
}

/**
 * Format error message
 */
export function formatErrorMessage(
  binaryName: string,
  error: string
): ProgressMessage {
  return {
    type: "complete",
    message: `[ERROR] ${binaryName}: Analysis failed - ${error}`,
    data: {
      binary_name: binaryName,
      error
    }
  }
}

/**
 * Format reconnaissance message
 */
export function formatReconMessage(
  totalFiles: number,
  binariesFound: number
): ProgressMessage {
  return {
    type: "progress",
    message: `[RECON] Scanned ${totalFiles} files, identified ${binariesFound} binaries`,
    data: {
      total_files: totalFiles,
      binaries_found: binariesFound
    }
  }
}

/**
 * Format priority list message
 */
export function formatPriorityMessage(
  targets: Array<{ name: string; score: number; type: string; size: string }>
): ProgressMessage {
  const topTargets = targets.slice(0, 5)
  const listStr = topTargets
    .map((t, i) => `  ${i + 1}. ${t.name} (score: ${t.score}) - ${t.type}, ${t.size}`)
    .join("\n")

  return {
    type: "progress",
    message: `[PRIORITY] Top targets:\n${listStr}`,
    data: {
      targets: topTargets
    }
  }
}

/**
 * Format aggregation message
 */
export function formatAggregationMessage(
  reportsCollected: number,
  duplicatesFound: number
): ProgressMessage {
  return {
    type: "progress",
    message: `[AGGREGATE] Collected ${reportsCollected} reports, found ${duplicatesFound} duplicate vulnerabilities`,
    data: {
      reports_collected: reportsCollected,
      duplicates_found: duplicatesFound
    }
  }
}

/**
 * Format SARIF generation message
 */
export function formatSARIFMessage(outputPath: string): ProgressMessage {
  return {
    type: "complete",
    message: `[REPORT] Generated SARIF report: ${outputPath}`,
    data: {
      output_path: outputPath
    }
  }
}

/**
 * Progress tracker class for stateful tracking
 */
export class ProgressTracker {
  private state: ProgressState

  constructor(totalBinaries: number) {
    this.state = createProgressState(totalBinaries)
  }

  start(): ProgressMessage {
    return formatStartMessage(this.state)
  }

  beginBinary(binaryName: string): ProgressMessage {
    this.state.current_binary = binaryName
    return formatProgressMessage(this.state, binaryName)
  }

  completeBinary(
    binaryName: string,
    findingsCount: number,
    severityBreakdown: Record<string, number>
  ): ProgressMessage {
    this.state = advanceProgress(this.state, binaryName, findingsCount)
    return formatCompletionMessage(binaryName, findingsCount, severityBreakdown)
  }

  error(binaryName: string, error: string): ProgressMessage {
    this.state = advanceProgress(this.state, binaryName, 0)
    return formatErrorMessage(binaryName, error)
  }

  summary(statistics: ReportStatistics): ProgressMessage {
    return formatSummaryMessage(this.state, statistics)
  }

  getState(): ProgressState {
    return { ...this.state }
  }

  getElapsedTime(): number {
    return Date.now() - this.state.start_time
  }
}
