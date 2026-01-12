/**
 * Sink Function Registry and Identifier
 * Requirements: 4.3, 5.1, 5.2, 5.3, 5.4
 * 
 * Defines dangerous sink functions and provides identification logic.
 */

import type { VulnerabilityType, SinkRegistry } from "./types"

/**
 * Comprehensive sink function registry
 * Requirements: 5.1, 5.2, 5.3, 5.4
 */
export const SINK_REGISTRY: SinkRegistry = {
  // Requirement 5.1: Command injection sinks
  command_injection: [
    // Direct command execution
    "system",
    "popen",
    "execve",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execvpe",
    // Process creation
    "fork",
    "vfork",
    "clone",
    "posix_spawn",
    "posix_spawnp",
    // Shell execution
    "sh",
    "bash",
    "execveat",
    // Windows specific
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "_wsystem",
    "_popen",
    "_wpopen"
  ],

  // Requirement 5.2: Buffer overflow sinks
  buffer_overflow: [
    // String copy functions
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "wcscpy",
    "wcsncpy",
    "wcscat",
    "wcsncat",
    // Formatted string functions (also format string, but buffer overflow risk)
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "swprintf",
    // Dangerous input functions
    "gets",
    "fgets",
    "getwd",
    "getenv",
    // Memory copy functions
    "memcpy",
    "memmove",
    "memset",
    "bcopy",
    "bzero",
    "wmemcpy",
    "wmemmove",
    // Network receive functions
    "read",
    "recv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    // File read functions
    "fread",
    "pread",
    "readv",
    // Scanf family
    "scanf",
    "fscanf",
    "sscanf",
    "vscanf",
    "vfscanf",
    "vsscanf"
  ],

  // Requirement 5.3: Format string sinks
  format_string: [
    // Printf family
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "vprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "dprintf",
    "vdprintf",
    // Wide character versions
    "wprintf",
    "fwprintf",
    "swprintf",
    "vwprintf",
    "vfwprintf",
    "vswprintf",
    // Logging functions
    "syslog",
    "vsyslog",
    // Error reporting
    "err",
    "errx",
    "warn",
    "warnx",
    "verr",
    "verrx",
    "vwarn",
    "vwarnx",
    // Windows specific
    "OutputDebugStringA",
    "OutputDebugStringW"
  ],

  // Requirement 5.4: Heap vulnerability sinks
  heap_vulnerability: [
    // Standard allocation
    "malloc",
    "calloc",
    "realloc",
    "free",
    "reallocarray",
    // Aligned allocation
    "memalign",
    "posix_memalign",
    "valloc",
    "pvalloc",
    "aligned_alloc",
    // C++ operators (when called as functions)
    "_Znwm",      // operator new
    "_Znam",      // operator new[]
    "_ZdlPv",     // operator delete
    "_ZdaPv",     // operator delete[]
    // Windows specific
    "HeapAlloc",
    "HeapFree",
    "HeapReAlloc",
    "LocalAlloc",
    "LocalFree",
    "GlobalAlloc",
    "GlobalFree",
    "VirtualAlloc",
    "VirtualFree"
  ]
}

/**
 * Flattened set of all sink functions for quick lookup
 */
const ALL_SINKS: Set<string> = new Set([
  ...SINK_REGISTRY.command_injection,
  ...SINK_REGISTRY.buffer_overflow,
  ...SINK_REGISTRY.format_string,
  ...SINK_REGISTRY.heap_vulnerability
])

/**
 * Reverse mapping from function name to vulnerability type(s)
 * Some functions may belong to multiple categories
 */
const SINK_TO_TYPE_MAP: Map<string, VulnerabilityType[]> = new Map()

// Build the reverse mapping
for (const [type, functions] of Object.entries(SINK_REGISTRY)) {
  for (const func of functions) {
    const existing = SINK_TO_TYPE_MAP.get(func) || []
    existing.push(type as VulnerabilityType)
    SINK_TO_TYPE_MAP.set(func, existing)
  }
}

/**
 * Check if a function name is a known sink
 */
export function isSinkFunction(functionName: string): boolean {
  if (!functionName) return false
  
  // Handle decorated names (strip leading underscore, @, etc.)
  const cleanName = cleanFunctionName(functionName)
  return ALL_SINKS.has(cleanName) || ALL_SINKS.has(functionName)
}

/**
 * Get vulnerability type(s) for a sink function
 * Returns null if not a sink function
 * 
 * Property 7: Sink Identification Correctness
 * For any import name, this function SHALL correctly categorize it into
 * the appropriate vulnerability type if it matches a known sink.
 */
export function identifySinkType(functionName: string): VulnerabilityType[] | null {
  if (!functionName) return null
  
  const cleanName = cleanFunctionName(functionName)
  
  // Try clean name first, then original
  const types = SINK_TO_TYPE_MAP.get(cleanName) || SINK_TO_TYPE_MAP.get(functionName)
  
  return types && types.length > 0 ? types : null
}

/**
 * Get the primary vulnerability type for a sink function
 * Returns the first/most relevant type
 */
export function getPrimarySinkType(functionName: string): VulnerabilityType | null {
  const types = identifySinkType(functionName)
  return types ? types[0] : null
}

/**
 * Clean function name by removing common decorations
 */
export function cleanFunctionName(name: string): string {
  if (!name) return ""
  
  // Remove leading underscore (common in some ABIs)
  let clean = name.replace(/^_+/, "")
  
  // Remove trailing @N (Windows stdcall decoration)
  clean = clean.replace(/@\d+$/, "")
  
  // Remove version suffixes like @GLIBC_2.0
  clean = clean.replace(/@.*$/, "")
  
  return clean
}

/**
 * Filter a list of import names to only sink functions
 */
export function filterSinkFunctions(imports: string[]): string[] {
  return imports.filter(isSinkFunction)
}

/**
 * Categorize a list of imports by vulnerability type
 */
export function categorizeImports(imports: string[]): Record<VulnerabilityType, string[]> {
  const result: Record<VulnerabilityType, string[]> = {
    command_injection: [],
    buffer_overflow: [],
    format_string: [],
    heap_vulnerability: []
  }
  
  for (const imp of imports) {
    const types = identifySinkType(imp)
    if (types) {
      for (const type of types) {
        if (!result[type].includes(imp)) {
          result[type].push(imp)
        }
      }
    }
  }
  
  return result
}

/**
 * Get all sink functions of a specific type
 */
export function getSinksByType(type: VulnerabilityType): string[] {
  return [...SINK_REGISTRY[type]]
}

/**
 * Get human-readable description of vulnerability type
 */
export function getVulnerabilityTypeDescription(type: VulnerabilityType): string {
  const descriptions: Record<VulnerabilityType, string> = {
    command_injection: "Command Injection",
    buffer_overflow: "Buffer Overflow",
    format_string: "Format String",
    heap_vulnerability: "Heap Vulnerability"
  }
  return descriptions[type]
}
