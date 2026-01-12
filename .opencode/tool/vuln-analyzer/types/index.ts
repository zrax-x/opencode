/**
 * Core TypeScript interfaces for Firmware Vulnerability Analyzer
 * Requirements: 1.3, 8.2, 10.1
 */

// ============================================================================
// Target List Types
// ============================================================================

export type BinaryType = "ELF" | "PE" | "SO" | "DLL"

export interface PriorityFactors {
  name_bonus: number
  size_bonus: number
  type_penalty: number
}

export interface TargetEntry {
  path: string
  filename: string
  file_type: string
  binary_type: BinaryType
  size_bytes: number
  priority_score: number
  priority_factors: PriorityFactors
}

// ============================================================================
// Sink Function Registry Types
// ============================================================================

export type VulnerabilityType =
  | "command_injection"
  | "buffer_overflow"
  | "format_string"
  | "heap_vulnerability"

export interface SinkRegistry {
  command_injection: string[]
  buffer_overflow: string[]
  format_string: string[]
  heap_vulnerability: string[]
}

export const SINK_FUNCTIONS: SinkRegistry = {
  command_injection: [
    "system", "popen", "execve", "execl", "execlp",
    "execle", "execv", "execvp", "execvpe", "fork",
    "vfork", "clone", "posix_spawn", "posix_spawnp"
  ],
  buffer_overflow: [
    "strcpy", "strncpy", "strcat", "strncat", "sprintf",
    "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
    "memcpy", "memmove", "memset", "bcopy", "bzero",
    "read", "recv", "recvfrom", "recvmsg"
  ],
  format_string: [
    "printf", "fprintf", "sprintf", "snprintf", "vprintf",
    "vfprintf", "vsprintf", "vsnprintf", "syslog", "err",
    "errx", "warn", "warnx"
  ],
  heap_vulnerability: [
    "malloc", "calloc", "realloc", "free", "memalign",
    "posix_memalign", "valloc", "pvalloc", "aligned_alloc"
  ]
}

// ============================================================================
// Vulnerability Finding Types
// ============================================================================

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
export type Confidence = "HIGH" | "MEDIUM" | "LOW"
export type Controllability = "FULL" | "PARTIAL" | "NONE"
export type ArgumentSourceType = "EXTERNAL" | "CONSTANT" | "AMBIGUOUS"

export interface ArgumentAnalysis {
  argument_index: number
  source: string
  controllability: Controllability
}

export interface VulnerabilityFinding {
  id: string
  binary_path: string
  function_name: string
  function_address: string
  call_address: string
  vulnerability_type: VulnerabilityType
  cwe_id: string
  severity: Severity
  confidence: Confidence
  sink_function: string
  pseudocode: string
  argument_analysis: ArgumentAnalysis
  call_chain: string[]
  exploitability: string
}

// ============================================================================
// Binary Report Types
// ============================================================================

export interface SeverityStats {
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  INFO: number
}

export interface TypeStats {
  command_injection: number
  buffer_overflow: number
  format_string: number
  heap_vulnerability: number
}

export interface ReportStatistics {
  total_sinks_analyzed: number
  total_findings: number
  by_severity: SeverityStats
  by_type: TypeStats
}

export interface BinaryReport {
  binary_path: string
  analysis_timestamp: string
  ida_version: string
  findings: VulnerabilityFinding[]
  statistics: ReportStatistics
}

// ============================================================================
// Aggregated Report Types
// ============================================================================

export interface AggregatedFinding extends VulnerabilityFinding {
  affected_binaries: string[]
}

export interface AggregatedReport {
  analysis_timestamp: string
  total_binaries_analyzed: number
  findings: AggregatedFinding[]
  statistics: ReportStatistics
}


// ============================================================================
// SARIF Report Types (SARIF 2.1.0)
// ============================================================================

export interface SARIFMessage {
  text: string
  markdown?: string
}

export interface SARIFArtifactLocation {
  uri: string
  uriBaseId?: string
}

export interface SARIFRegion {
  startLine?: number
  startColumn?: number
  endLine?: number
  endColumn?: number
  snippet?: {
    text: string
  }
}

export interface SARIFPhysicalLocation {
  artifactLocation: SARIFArtifactLocation
  region?: SARIFRegion
}

export interface SARIFLocation {
  physicalLocation?: SARIFPhysicalLocation
  message?: SARIFMessage
}

export interface SARIFCodeFlowThreadFlowLocation {
  location: SARIFLocation
  nestingLevel?: number
}

export interface SARIFThreadFlow {
  locations: SARIFCodeFlowThreadFlowLocation[]
}

export interface SARIFCodeFlow {
  threadFlows: SARIFThreadFlow[]
  message?: SARIFMessage
}

export type SARIFLevel = "none" | "note" | "warning" | "error"

export interface SARIFResult {
  ruleId: string
  level: SARIFLevel
  message: SARIFMessage
  locations: SARIFLocation[]
  codeFlows?: SARIFCodeFlow[]
  relatedLocations?: SARIFLocation[]
  fingerprints?: Record<string, string>
}

export interface SARIFReportingDescriptor {
  id: string
  name?: string
  shortDescription?: SARIFMessage
  fullDescription?: SARIFMessage
  helpUri?: string
  defaultConfiguration?: {
    level: SARIFLevel
  }
}

export interface SARIFToolDriver {
  name: string
  version: string
  informationUri: string
  rules: SARIFReportingDescriptor[]
}

export interface SARIFTool {
  driver: SARIFToolDriver
}

export interface SARIFInvocation {
  executionSuccessful: boolean
  startTimeUtc: string
  endTimeUtc: string
  workingDirectory?: SARIFArtifactLocation
}

export interface SARIFRun {
  tool: SARIFTool
  results: SARIFResult[]
  invocations: SARIFInvocation[]
}

export interface SARIFReport {
  $schema: string
  version: "2.1.0"
  runs: SARIFRun[]
}

// ============================================================================
// CWE Mapping Types
// ============================================================================

export interface CWEMapping {
  id: string
  name: string
  description: string
}

export const CWE_MAPPINGS: Record<VulnerabilityType, CWEMapping> = {
  command_injection: {
    id: "CWE-78",
    name: "OS Command Injection",
    description: "Improper Neutralization of Special Elements used in an OS Command"
  },
  buffer_overflow: {
    id: "CWE-120",
    name: "Buffer Copy without Checking Size of Input",
    description: "Classic Buffer Overflow"
  },
  format_string: {
    id: "CWE-134",
    name: "Use of Externally-Controlled Format String",
    description: "Uncontrolled Format String"
  },
  heap_vulnerability: {
    id: "CWE-122",
    name: "Heap-based Buffer Overflow",
    description: "Heap-based Buffer Overflow"
  }
}

// ============================================================================
// Progress Tracking Types
// ============================================================================

export interface ProgressState {
  total_binaries: number
  current_index: number
  current_binary: string
  start_time: number
  findings_per_binary: Record<string, number>
}

export interface ProgressMessage {
  type: "start" | "progress" | "complete" | "summary"
  message: string
  data?: Record<string, unknown>
}
