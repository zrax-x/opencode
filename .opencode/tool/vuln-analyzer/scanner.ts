/**
 * Binary File Scanner and Filter
 * Requirements: 1.1, 1.2, 1.4
 * 
 * Implements recursive directory scanning and binary file identification
 * using the `file` command to detect ELF/PE executables and shared libraries.
 */

import { execSync } from "child_process"
import { statSync } from "fs"
import type { BinaryType, TargetEntry, PriorityFactors } from "./types"

// Minimum file size in bytes (1KB)
const MIN_FILE_SIZE = 1024

/**
 * File type patterns for binary detection
 */
const BINARY_PATTERNS = {
  ELF: /ELF\s+\d+-bit\s+(LSB|MSB)\s+(executable|shared object|pie executable)/i,
  PE: /PE32\+?\s+executable/i,
  SO: /ELF\s+\d+-bit\s+(LSB|MSB)\s+shared object/i,
  DLL: /PE32\+?\s+executable.*DLL/i
}

/**
 * Parse the output of the `file` command to determine binary type
 */
export function parseBinaryType(fileOutput: string): BinaryType | null {
  // Check for DLL first (more specific than PE)
  if (BINARY_PATTERNS.DLL.test(fileOutput)) {
    return "DLL"
  }
  // Check for PE executable
  if (BINARY_PATTERNS.PE.test(fileOutput)) {
    return "PE"
  }
  // Check for shared object (.so)
  if (BINARY_PATTERNS.SO.test(fileOutput) && !fileOutput.includes("executable")) {
    return "SO"
  }
  // Check for ELF executable
  if (BINARY_PATTERNS.ELF.test(fileOutput)) {
    return "ELF"
  }
  return null
}

/**
 * Check if a file type string indicates a binary we should analyze
 */
export function isBinaryFile(fileOutput: string): boolean {
  return parseBinaryType(fileOutput) !== null
}

/**
 * Execute the `file` command on a single file
 */
export function getFileType(filePath: string): string {
  try {
    const output = execSync(`file -b "${filePath}"`, {
      encoding: "utf-8",
      timeout: 5000
    })
    return output.trim()
  } catch {
    return ""
  }
}

/**
 * Get file size in bytes
 */
export function getFileSize(filePath: string): number {
  try {
    const stats = statSync(filePath)
    return stats.size
  } catch {
    return 0
  }
}

/**
 * Extract filename from path
 */
export function extractFilename(filePath: string): string {
  const parts = filePath.split("/")
  return parts[parts.length - 1] || filePath
}

/**
 * Scan a directory recursively and return all file paths
 */
export function scanDirectory(targetPath: string): string[] {
  try {
    const output = execSync(`find "${targetPath}" -type f 2>/dev/null`, {
      encoding: "utf-8",
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer for large directories
    })
    return output
      .trim()
      .split("\n")
      .filter(line => line.length > 0)
  } catch {
    return []
  }
}

/**
 * Filter files to include only binaries above minimum size
 * Requirements: 1.2, 1.4
 */
export function filterBinaries(
  files: string[],
  minSize: number = MIN_FILE_SIZE
): Array<{ path: string; fileType: string; binaryType: BinaryType; size: number }> {
  const results: Array<{ path: string; fileType: string; binaryType: BinaryType; size: number }> = []

  for (const filePath of files) {
    const size = getFileSize(filePath)
    
    // Skip files smaller than minimum size (Requirement 1.4)
    if (size < minSize) {
      continue
    }

    const fileType = getFileType(filePath)
    const binaryType = parseBinaryType(fileType)

    // Only include recognized binary types (Requirement 1.2)
    if (binaryType !== null) {
      results.push({
        path: filePath,
        fileType,
        binaryType,
        size
      })
    }
  }

  return results
}

/**
 * Create a TargetEntry with default priority factors (to be calculated later)
 */
export function createTargetEntry(
  path: string,
  fileType: string,
  binaryType: BinaryType,
  size: number
): TargetEntry {
  const defaultFactors: PriorityFactors = {
    name_bonus: 0,
    size_bonus: 0,
    type_penalty: 0
  }

  return {
    path,
    filename: extractFilename(path),
    file_type: fileType,
    binary_type: binaryType,
    size_bytes: size,
    priority_score: 50, // Base score, will be recalculated
    priority_factors: defaultFactors
  }
}

/**
 * Main scanning function: scan directory and return filtered binary targets
 * Requirements: 1.1, 1.2, 1.3, 1.4
 */
export function scanForBinaries(targetPath: string): TargetEntry[] {
  // Step 1: Recursively scan directory (Requirement 1.1)
  const allFiles = scanDirectory(targetPath)

  // Step 2: Filter for binaries and apply size filter (Requirements 1.2, 1.4)
  const binaries = filterBinaries(allFiles)

  // Step 3: Create TargetEntry for each binary (Requirement 1.3)
  return binaries.map(b => createTargetEntry(b.path, b.fileType, b.binaryType, b.size))
}
