/**
 * Priority Scoring Module
 * Requirements: 2.1, 2.2, 2.3, 2.4
 * 
 * Implements priority scoring algorithm for binary analysis targets.
 * Higher scores indicate higher priority for vulnerability analysis.
 */

import type { BinaryType, TargetEntry, PriorityFactors } from "./types"
import { isSharedLibrary } from "./filter"

// Base score for all binaries
const BASE_SCORE = 50

// Score bounds
const MIN_SCORE = 0
const MAX_SCORE = 100

/**
 * Network-related keywords and their bonus scores
 * Requirement 2.2: Higher scores for network-related binaries
 */
const NAME_BONUSES: Array<{ patterns: RegExp[]; bonus: number }> = [
  {
    // HTTP/Web related - highest priority
    patterns: [/http/i, /web/i, /cgi/i, /nginx/i, /apache/i, /lighttpd/i],
    bonus: 30
  },
  {
    // Remote access protocols
    patterns: [/ssh/i, /telnet/i, /ftp/i, /tftp/i, /sftp/i],
    bonus: 25
  },
  {
    // Authentication related
    patterns: [/login/i, /auth/i, /passwd/i, /shadow/i, /pam/i],
    bonus: 20
  },
  {
    // Administration/Configuration
    patterns: [/admin/i, /config/i, /setup/i, /manage/i],
    bonus: 15
  },
  {
    // Daemon/Service processes
    patterns: [/daemon/i, /server/i, /service/i, /d$/],
    bonus: 10
  },
  {
    // Network utilities
    patterns: [/socket/i, /net/i, /dns/i, /dhcp/i, /snmp/i],
    bonus: 10
  }
]

/**
 * Size thresholds and their bonus/penalty scores
 * Requirement 2.3: Higher scores for larger binaries
 */
const SIZE_THRESHOLDS = {
  LARGE: { threshold: 1024 * 1024, bonus: 15 },      // > 1MB: +15
  MEDIUM: { threshold: 512 * 1024, bonus: 10 },      // > 500KB: +10
  SMALL: { threshold: 100 * 1024, bonus: 5 },        // > 100KB: +5
  TINY: { threshold: 10 * 1024, penalty: 10 }        // < 10KB: -10
}

/**
 * Type penalties
 * Requirement 2.4: Lower scores for shared libraries
 */
const TYPE_PENALTIES: Record<BinaryType, number> = {
  ELF: 0,
  PE: 0,
  SO: 20,
  DLL: 20
}

/**
 * Calculate name-based bonus score
 * Requirement 2.2
 */
export function calculateNameBonus(filename: string): number {
  if (!filename) return 0

  const lowerFilename = filename.toLowerCase()
  
  for (const { patterns, bonus } of NAME_BONUSES) {
    for (const pattern of patterns) {
      if (pattern.test(lowerFilename)) {
        return bonus
      }
    }
  }
  
  return 0
}

/**
 * Calculate size-based bonus/penalty score
 * Requirement 2.3
 */
export function calculateSizeBonus(sizeBytes: number): number {
  if (sizeBytes > SIZE_THRESHOLDS.LARGE.threshold) {
    return SIZE_THRESHOLDS.LARGE.bonus
  }
  if (sizeBytes > SIZE_THRESHOLDS.MEDIUM.threshold) {
    return SIZE_THRESHOLDS.MEDIUM.bonus
  }
  if (sizeBytes > SIZE_THRESHOLDS.SMALL.threshold) {
    return SIZE_THRESHOLDS.SMALL.bonus
  }
  if (sizeBytes < SIZE_THRESHOLDS.TINY.threshold) {
    return -SIZE_THRESHOLDS.TINY.penalty
  }
  return 0
}

/**
 * Calculate type-based penalty score
 * Requirement 2.4
 */
export function calculateTypePenalty(binaryType: BinaryType): number {
  return TYPE_PENALTIES[binaryType] || 0
}

/**
 * Calculate all priority factors for a binary
 */
export function calculatePriorityFactors(
  filename: string,
  sizeBytes: number,
  binaryType: BinaryType
): PriorityFactors {
  return {
    name_bonus: calculateNameBonus(filename),
    size_bonus: calculateSizeBonus(sizeBytes),
    type_penalty: calculateTypePenalty(binaryType)
  }
}

/**
 * Calculate final priority score from factors
 * 
 * Property 4: Priority Score Validity
 * For any binary, the priority score SHALL be within [0, 100]
 */
export function calculatePriorityScore(factors: PriorityFactors): number {
  const rawScore = BASE_SCORE + factors.name_bonus + factors.size_bonus - factors.type_penalty
  
  // Clamp to valid range
  return Math.max(MIN_SCORE, Math.min(MAX_SCORE, rawScore))
}

/**
 * Update a TargetEntry with calculated priority score
 */
export function scoreBinary(entry: TargetEntry): TargetEntry {
  const factors = calculatePriorityFactors(
    entry.filename,
    entry.size_bytes,
    entry.binary_type
  )
  
  const score = calculatePriorityScore(factors)
  
  return {
    ...entry,
    priority_score: score,
    priority_factors: factors
  }
}

/**
 * Score and sort a list of target entries by priority (descending)
 */
export function scoreAndSortTargets(entries: TargetEntry[]): TargetEntry[] {
  return entries
    .map(scoreBinary)
    .sort((a, b) => b.priority_score - a.priority_score)
}

/**
 * Get top N targets by priority
 */
export function getTopTargets(entries: TargetEntry[], limit: number = 10): TargetEntry[] {
  const sorted = scoreAndSortTargets(entries)
  return sorted.slice(0, limit)
}
