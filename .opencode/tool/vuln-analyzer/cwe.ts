/**
 * CWE Mapping and Severity Classification Module
 * Requirements: 7.2, 7.3, 7.4, 7.5
 * 
 * Maps vulnerability types to CWE identifiers and classifies severity
 * based on argument controllability.
 */

import type { 
  VulnerabilityType, 
  Severity, 
  ArgumentSourceType,
  CWEMapping 
} from "./types"

/**
 * Comprehensive CWE mappings for each vulnerability type
 * Requirement 7.5
 */
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

/**
 * Extended CWE mappings for more specific vulnerability subtypes
 */
export const EXTENDED_CWE_MAPPINGS: Record<string, CWEMapping> = {
  // Buffer overflow subtypes
  stack_buffer_overflow: {
    id: "CWE-121",
    name: "Stack-based Buffer Overflow",
    description: "Stack-based Buffer Overflow"
  },
  heap_buffer_overflow: {
    id: "CWE-122",
    name: "Heap-based Buffer Overflow",
    description: "Heap-based Buffer Overflow"
  },
  off_by_one: {
    id: "CWE-193",
    name: "Off-by-one Error",
    description: "Off-by-one Error"
  },
  
  // Heap vulnerability subtypes
  use_after_free: {
    id: "CWE-416",
    name: "Use After Free",
    description: "Use After Free"
  },
  double_free: {
    id: "CWE-415",
    name: "Double Free",
    description: "Double Free"
  },
  memory_leak: {
    id: "CWE-401",
    name: "Memory Leak",
    description: "Missing Release of Memory after Effective Lifetime"
  },
  
  // Integer issues
  integer_overflow: {
    id: "CWE-190",
    name: "Integer Overflow or Wraparound",
    description: "Integer Overflow or Wraparound"
  },
  integer_underflow: {
    id: "CWE-191",
    name: "Integer Underflow",
    description: "Integer Underflow (Wrap or Wraparound)"
  },
  
  // Other common vulnerabilities
  null_pointer_dereference: {
    id: "CWE-476",
    name: "NULL Pointer Dereference",
    description: "NULL Pointer Dereference"
  },
  path_traversal: {
    id: "CWE-22",
    name: "Path Traversal",
    description: "Improper Limitation of a Pathname to a Restricted Directory"
  }
}

/**
 * Get CWE mapping for a vulnerability type
 * 
 * Property 9: CWE Mapping Correctness
 * For any vulnerability type, this function SHALL return the correct CWE mapping.
 */
export function getCWEMapping(vulnType: VulnerabilityType): CWEMapping {
  return CWE_MAPPINGS[vulnType]
}

/**
 * Get CWE ID for a vulnerability type
 */
export function getCWEId(vulnType: VulnerabilityType): string {
  return CWE_MAPPINGS[vulnType].id
}

/**
 * Get extended CWE mapping for a specific subtype
 */
export function getExtendedCWEMapping(subtype: string): CWEMapping | null {
  return EXTENDED_CWE_MAPPINGS[subtype] || null
}

/**
 * Classify argument source type based on source description
 */
export function classifyArgumentSource(sourceDescription: string): ArgumentSourceType {
  const lowerSource = sourceDescription.toLowerCase()
  
  // External input indicators
  const externalIndicators = [
    "user", "input", "network", "socket", "recv", "read",
    "file", "stdin", "argv", "argc", "environment", "env",
    "getenv", "http", "request", "query", "param", "form",
    "cookie", "header", "body", "payload", "buffer", "data",
    "external", "untrusted", "remote", "client"
  ]
  
  // Constant indicators
  const constantIndicators = [
    "constant", "const", "literal", "hardcoded", "static",
    "fixed", "embedded", "compiled", "immediate"
  ]
  
  // Check for external input
  for (const indicator of externalIndicators) {
    if (lowerSource.includes(indicator)) {
      return "EXTERNAL"
    }
  }
  
  // Check for constants
  for (const indicator of constantIndicators) {
    if (lowerSource.includes(indicator)) {
      return "CONSTANT"
    }
  }
  
  // Default to ambiguous
  return "AMBIGUOUS"
}

/**
 * Classify severity based on argument source type
 * 
 * Property 8: Severity Classification Correctness
 * - External input → HIGH
 * - Hardcoded constant → FALSE POSITIVE (excluded, returns null)
 * - Ambiguous → MEDIUM
 * 
 * Requirements: 7.2, 7.3, 7.4
 */
export function classifySeverity(sourceType: ArgumentSourceType): Severity | null {
  switch (sourceType) {
    case "EXTERNAL":
      // Requirement 7.2: External input sources are HIGH severity
      return "HIGH"
    case "CONSTANT":
      // Requirement 7.3: Hardcoded constants are FALSE POSITIVE
      return null
    case "AMBIGUOUS":
      // Requirement 7.4: Ambiguous sources are MEDIUM severity
      return "MEDIUM"
    default:
      return "MEDIUM"
  }
}

/**
 * Determine if a finding should be excluded as false positive
 */
export function isFalsePositive(sourceType: ArgumentSourceType): boolean {
  return sourceType === "CONSTANT"
}

/**
 * Get severity level for SARIF output
 */
export function getSARIFLevel(severity: Severity): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error"
    case "MEDIUM":
      return "warning"
    case "LOW":
      return "note"
    case "INFO":
      return "none"
    default:
      return "warning"
  }
}

/**
 * Get human-readable severity description
 */
export function getSeverityDescription(severity: Severity): string {
  const descriptions: Record<Severity, string> = {
    CRITICAL: "Critical - Immediate exploitation possible",
    HIGH: "High - Likely exploitable with user-controlled input",
    MEDIUM: "Medium - Potentially exploitable, requires further analysis",
    LOW: "Low - Limited exploitation potential",
    INFO: "Informational - No direct security impact"
  }
  return descriptions[severity]
}

/**
 * Calculate overall severity considering multiple factors
 */
export function calculateOverallSeverity(
  vulnType: VulnerabilityType,
  sourceType: ArgumentSourceType,
  hasCallChain: boolean
): Severity | null {
  // First check if it's a false positive
  if (isFalsePositive(sourceType)) {
    return null
  }
  
  // Base severity from source type
  let baseSeverity = classifySeverity(sourceType)
  if (!baseSeverity) return null
  
  // Elevate command injection to CRITICAL if external input
  if (vulnType === "command_injection" && sourceType === "EXTERNAL") {
    return "CRITICAL"
  }
  
  // Elevate if there's a clear call chain from entry point
  if (hasCallChain && baseSeverity === "MEDIUM") {
    return "HIGH"
  }
  
  return baseSeverity
}
