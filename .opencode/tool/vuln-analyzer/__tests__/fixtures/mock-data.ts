/**
 * Mock data for testing the vulnerability analyzer
 */

import type {
  TargetEntry,
  VulnerabilityFinding,
  BinaryReport,
  AggregatedFinding
} from "../../types"

/**
 * Sample file command outputs for testing binary detection
 */
export const SAMPLE_FILE_OUTPUTS = {
  elf_executable: "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked",
  elf_pie: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked",
  elf_shared: "ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux)",
  pe_executable: "PE32+ executable (console) x86-64, for MS Windows",
  pe_dll: "PE32+ executable (DLL) (console) x86-64, for MS Windows",
  text_file: "ASCII text",
  png_image: "PNG image data, 100 x 100, 8-bit/color RGBA",
  shell_script: "Bourne-Again shell script, ASCII text executable",
  python_script: "Python script, ASCII text executable"
}

/**
 * Sample target entries for testing priority scoring
 */
export const SAMPLE_TARGETS: TargetEntry[] = [
  {
    path: "/firmware/bin/httpd",
    filename: "httpd",
    file_type: SAMPLE_FILE_OUTPUTS.elf_executable,
    binary_type: "ELF",
    size_bytes: 2 * 1024 * 1024, // 2MB
    priority_score: 0,
    priority_factors: { name_bonus: 0, size_bonus: 0, type_penalty: 0 }
  },
  {
    path: "/firmware/bin/sshd",
    filename: "sshd",
    file_type: SAMPLE_FILE_OUTPUTS.elf_executable,
    binary_type: "ELF",
    size_bytes: 1.5 * 1024 * 1024, // 1.5MB
    priority_score: 0,
    priority_factors: { name_bonus: 0, size_bonus: 0, type_penalty: 0 }
  },
  {
    path: "/firmware/lib/libcrypto.so",
    filename: "libcrypto.so",
    file_type: SAMPLE_FILE_OUTPUTS.elf_shared,
    binary_type: "SO",
    size_bytes: 3 * 1024 * 1024, // 3MB
    priority_score: 0,
    priority_factors: { name_bonus: 0, size_bonus: 0, type_penalty: 0 }
  },
  {
    path: "/firmware/bin/config_tool",
    filename: "config_tool",
    file_type: SAMPLE_FILE_OUTPUTS.elf_executable,
    binary_type: "ELF",
    size_bytes: 50 * 1024, // 50KB
    priority_score: 0,
    priority_factors: { name_bonus: 0, size_bonus: 0, type_penalty: 0 }
  },
  {
    path: "/firmware/bin/tiny_util",
    filename: "tiny_util",
    file_type: SAMPLE_FILE_OUTPUTS.elf_executable,
    binary_type: "ELF",
    size_bytes: 5 * 1024, // 5KB
    priority_score: 0,
    priority_factors: { name_bonus: 0, size_bonus: 0, type_penalty: 0 }
  }
]

/**
 * Sample import lists for testing sink identification
 */
export const SAMPLE_IMPORTS = {
  vulnerable: [
    "printf", "strcpy", "system", "malloc", "free",
    "recv", "sprintf", "memcpy", "popen", "gets"
  ],
  safe: [
    "strlen", "strcmp", "strdup", "fopen", "fclose",
    "pthread_create", "pthread_join", "sleep", "exit"
  ],
  mixed: [
    "printf", "strlen", "strcpy", "strcmp", "system",
    "malloc", "strdup", "free", "fopen", "recv"
  ]
}

/**
 * Sample vulnerability finding for testing
 */
export const SAMPLE_FINDING: VulnerabilityFinding = {
  id: "httpd_00401234_strcpy_abc123",
  binary_path: "/firmware/bin/httpd",
  function_name: "parse_request",
  function_address: "0x00401234",
  call_address: "0x00401250",
  vulnerability_type: "buffer_overflow",
  cwe_id: "CWE-120",
  severity: "HIGH",
  confidence: "HIGH",
  sink_function: "strcpy",
  pseudocode: `void parse_request(char *request) {
  char buffer[64];
  strcpy(buffer, request);  // VULNERABLE
  process_buffer(buffer);
}`,
  argument_analysis: {
    argument_index: 1,
    source: "User input from recv() at 0x00401100",
    controllability: "FULL"
  },
  call_chain: ["main", "handle_connection", "parse_request"],
  exploitability: "High - direct user input to strcpy with fixed-size buffer"
}

/**
 * Sample binary report for testing
 */
export const SAMPLE_REPORT: BinaryReport = {
  binary_path: "/firmware/bin/httpd",
  analysis_timestamp: "2024-01-15T10:30:00Z",
  ida_version: "8.3",
  findings: [SAMPLE_FINDING],
  statistics: {
    total_sinks_analyzed: 15,
    total_findings: 1,
    by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
    by_type: { command_injection: 0, buffer_overflow: 1, format_string: 0, heap_vulnerability: 0 }
  }
}

/**
 * Sample aggregated finding for testing deduplication
 */
export const SAMPLE_AGGREGATED_FINDING: AggregatedFinding = {
  ...SAMPLE_FINDING,
  affected_binaries: ["/firmware/bin/httpd", "/firmware/bin/ftpd"]
}

/**
 * Create a mock finding with customizable properties
 */
export function createMockFinding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    ...SAMPLE_FINDING,
    id: `mock_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    ...overrides
  }
}

/**
 * Create a mock report with customizable properties
 */
export function createMockReport(
  binaryPath: string,
  findings: VulnerabilityFinding[] = []
): BinaryReport {
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  const byType = { command_injection: 0, buffer_overflow: 0, format_string: 0, heap_vulnerability: 0 }

  for (const f of findings) {
    if (f.severity in bySeverity) {
      bySeverity[f.severity as keyof typeof bySeverity]++
    }
    if (f.vulnerability_type in byType) {
      byType[f.vulnerability_type as keyof typeof byType]++
    }
  }

  return {
    binary_path: binaryPath,
    analysis_timestamp: new Date().toISOString(),
    ida_version: "8.3",
    findings,
    statistics: {
      total_sinks_analyzed: findings.length * 5,
      total_findings: findings.length,
      by_severity: bySeverity,
      by_type: byType
    }
  }
}
