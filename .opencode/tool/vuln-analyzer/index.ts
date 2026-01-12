/**
 * Firmware Vulnerability Analyzer
 * 
 * Main entry point exporting all modules for the vulnerability analysis system.
 */

// Types (excluding CWE_MAPPINGS which is also in cwe.ts)
export type {
  BinaryType,
  PriorityFactors,
  TargetEntry,
  VulnerabilityType,
  SinkRegistry,
  Severity,
  Confidence,
  Controllability,
  ArgumentSourceType,
  ArgumentAnalysis,
  VulnerabilityFinding,
  SeverityStats,
  TypeStats,
  ReportStatistics,
  BinaryReport,
  AggregatedFinding,
  AggregatedReport,
  SARIFReport,
  SARIFRun,
  SARIFResult,
  CWEMapping,
  ProgressState,
  ProgressMessage
} from "./types"

export { SINK_FUNCTIONS } from "./types"

// Scanner module
export {
  scanDirectory,
  getFileType,
  getFileSize,
  extractFilename,
  filterBinaries,
  createTargetEntry,
  scanForBinaries
} from "./scanner"

// Filter module (use filter's versions as canonical)
export {
  MIN_FILE_SIZE,
  BINARY_PATTERNS,
  parseBinaryType,
  isBinaryFile,
  meetsMinimumSize,
  shouldIncludeFile,
  getBinaryTypeDescription,
  isSharedLibrary
} from "./filter"

// Priority module
export {
  calculateNameBonus,
  calculateSizeBonus,
  calculateTypePenalty,
  calculatePriorityFactors,
  calculatePriorityScore,
  scoreBinary,
  scoreAndSortTargets,
  getTopTargets
} from "./priority"

// Sinks module
export {
  SINK_REGISTRY,
  isSinkFunction,
  identifySinkType,
  getPrimarySinkType,
  cleanFunctionName,
  filterSinkFunctions,
  categorizeImports,
  getSinksByType,
  getVulnerabilityTypeDescription
} from "./sinks"

// CWE module
export {
  CWE_MAPPINGS,
  EXTENDED_CWE_MAPPINGS,
  getCWEMapping,
  getCWEId,
  getExtendedCWEMapping,
  classifyArgumentSource,
  classifySeverity,
  isFalsePositive,
  getSARIFLevel,
  getSeverityDescription,
  calculateOverallSeverity
} from "./cwe"

// Report module
export {
  generateFindingId,
  generateReportFilename,
  createEmptySeverityStats,
  createEmptyTypeStats,
  calculateStatistics,
  createBinaryReport,
  validateFinding,
  serializeReport,
  saveReport,
  createEmptyReport,
  createFinding
} from "./report"

// Aggregator module
export {
  generateDeduplicationKey,
  areDuplicates,
  loadReport,
  collectReports,
  deduplicateFindings,
  calculateAggregatedStatistics,
  aggregateReports,
  getDuplicateSummary,
  sortBySeverity,
  filterBySeverity
} from "./aggregator"

// SARIF module
export {
  generateSARIFReport,
  serializeSARIF,
  saveSARIFReport,
  parseSARIF,
  extractFindingsFromSARIF
} from "./sarif"

// Queue module
export type { TaskStatus, AnalysisTask, QueueConfig } from "./queue"
export {
  DEFAULT_QUEUE_CONFIG,
  createTasks,
  verifyTaskOrder,
  TaskQueue,
  createTaskPrompt
} from "./queue"

// Progress module
export {
  createProgressState,
  formatDuration,
  formatStartMessage,
  formatProgressMessage,
  formatCompletionMessage,
  formatSummaryMessage,
  advanceProgress,
  formatErrorMessage,
  formatReconMessage,
  formatPriorityMessage,
  formatAggregationMessage,
  formatSARIFMessage,
  ProgressTracker
} from "./progress"
