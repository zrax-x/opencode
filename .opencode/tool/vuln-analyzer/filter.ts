/**
 * Binary Filter Module
 * Requirements: 1.2, 1.4
 * 
 * Provides filtering logic for binary files based on type and size.
 */

import type { BinaryType } from "./types"

// Minimum file size in bytes (1KB) - Requirement 1.4
export const MIN_FILE_SIZE = 1024

/**
 * File type patterns for binary detection
 * These patterns match the output of the `file` command
 */
export const BINARY_PATTERNS: Record<BinaryType, RegExp> = {
  ELF: /ELF\s+\d+-bit\s+(LSB|MSB)\s+(executable|pie executable)/i,
  PE: /PE32\+?\s+executable(?!.*DLL)/i,
  SO: /ELF\s+\d+-bit\s+(LSB|MSB)\s+shared object/i,
  DLL: /PE32\+?\s+executable.*DLL/i
}

/**
 * Parse the output of the `file` command to determine binary type
 * Returns null if the file is not a recognized binary type
 * 
 * Property 1: Binary Filter Correctness
 * For any output from the `file` command, this function SHALL only return
 * a BinaryType for entries that match ELF executable, PE executable,
 * shared library (.so), or DLL patterns.
 */
export function parseBinaryType(fileOutput: string): BinaryType | null {
  if (!fileOutput || typeof fileOutput !== "string") {
    return null
  }

  // Check for DLL first (more specific than PE)
  if (BINARY_PATTERNS.DLL.test(fileOutput)) {
    return "DLL"
  }
  
  // Check for PE executable (but not DLL)
  if (BINARY_PATTERNS.PE.test(fileOutput)) {
    return "PE"
  }
  
  // Check for shared object (.so) - must be shared object but not executable
  if (BINARY_PATTERNS.SO.test(fileOutput) && 
      !fileOutput.toLowerCase().includes("executable") &&
      !fileOutput.toLowerCase().includes("pie executable")) {
    return "SO"
  }
  
  // Check for ELF executable (including PIE executables)
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
 * Check if a file size meets the minimum requirement
 * 
 * Property 3: Size Filter Correctness
 * For any file with size less than 1024 bytes, this function SHALL return false.
 */
export function meetsMinimumSize(sizeBytes: number): boolean {
  return sizeBytes >= MIN_FILE_SIZE
}

/**
 * Combined filter: check both binary type and size
 */
export function shouldIncludeFile(fileOutput: string, sizeBytes: number): boolean {
  return isBinaryFile(fileOutput) && meetsMinimumSize(sizeBytes)
}

/**
 * Get human-readable description of binary type
 */
export function getBinaryTypeDescription(binaryType: BinaryType): string {
  const descriptions: Record<BinaryType, string> = {
    ELF: "ELF Executable",
    PE: "PE Executable",
    SO: "Shared Library (.so)",
    DLL: "Dynamic Link Library (.dll)"
  }
  return descriptions[binaryType]
}

/**
 * Check if a binary type is a shared library
 */
export function isSharedLibrary(binaryType: BinaryType): boolean {
  return binaryType === "SO" || binaryType === "DLL"
}
