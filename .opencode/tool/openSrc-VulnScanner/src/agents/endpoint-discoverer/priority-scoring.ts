/**
 * Priority Scoring Module
 * 
 * Calculates priority scores for endpoints based on attack surface indicators
 * Higher scores indicate higher priority for analysis
 */

import type { Endpoint } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('PriorityScoring');

/**
 * Base score for all endpoints
 */
const BASE_SCORE = 50;

/**
 * High-risk keywords and their bonus scores
 */
const HIGH_RISK_KEYWORDS: Record<string, number> = {
  // Administrative functions
  'admin': 30,
  '管理': 30,
  'administrator': 30,
  
  // Authentication/Authorization
  'auth': 25,
  'login': 25,
  'logout': 25,
  '认证': 25,
  '登录': 25,
  'signin': 25,
  'signup': 25,
  'register': 25,
  
  // File operations
  'upload': 20,
  'file': 20,
  '上传': 20,
  '文件': 20,
  'download': 15,
  'read': 15,
  '下载': 15,
  '读取': 15,
  
  // Command execution
  'exec': 25,
  'execute': 25,
  'cmd': 25,
  'command': 25,
  '执行': 25,
  'eval': 20,
  'run': 20,
  'shell': 25,
  
  // Configuration
  'config': 15,
  'settings': 15,
  'setup': 15,
  '配置': 15,
  
  // User management
  'user': 10,
  'users': 10,
  'account': 10,
  'profile': 10,
  
  // Data operations
  'delete': 15,
  'remove': 15,
  'update': 10,
  'modify': 10,
  'create': 10,
  
  // System operations
  'system': 15,
  'process': 15,
  'service': 10,
  'daemon': 10,
};

/**
 * Accessibility bonus scores
 */
const ACCESSIBILITY_BONUS = {
  NO_AUTH: 20,        // Publicly accessible
  WEAK_AUTH: 10,      // Has auth but weak
  STRONG_AUTH: 0,     // Strong authentication
};

/**
 * Calculate name bonus based on route pattern and handler function
 */
function calculateNameBonus(endpoint: Endpoint): number {
  let bonus = 0;
  
  // Combine route pattern and handler function for analysis
  const textToAnalyze = `${endpoint.routePattern} ${endpoint.handlerFunction}`.toLowerCase();
  
  // Check for high-risk keywords
  for (const [keyword, score] of Object.entries(HIGH_RISK_KEYWORDS)) {
    if (textToAnalyze.includes(keyword.toLowerCase())) {
      bonus = Math.max(bonus, score); // Take highest matching score
    }
  }
  
  return bonus;
}

/**
 * Calculate accessibility bonus based on authentication requirements
 */
function calculateAccessibilityBonus(endpoint: Endpoint): number {
  if (!endpoint.requiresAuth) {
    return ACCESSIBILITY_BONUS.NO_AUTH;
  }
  
  // TODO: In future, detect weak auth vs strong auth
  // For now, assume all auth is strong
  return ACCESSIBILITY_BONUS.STRONG_AUTH;
}

/**
 * Calculate size penalty based on handler function complexity
 * Note: This requires reading the actual function code
 * For now, we'll return 0 and implement later if needed
 */
function calculateSizePenalty(_endpoint: Endpoint): number {
  // TODO: Implement function size analysis
  // - Read handler function code
  // - Count lines
  // - Apply penalty/bonus based on size
  return 0;
}

/**
 * Calculate priority score for a single endpoint
 */
export function calculatePriority(endpoint: Endpoint): number {
  const nameBonus = calculateNameBonus(endpoint);
  const accessibilityBonus = calculateAccessibilityBonus(endpoint);
  const sizePenalty = calculateSizePenalty(endpoint);
  
  const score = BASE_SCORE + nameBonus + accessibilityBonus + sizePenalty;
  
  logger.debug('Calculated priority score', {
    endpoint: endpoint.routePattern,
    baseScore: BASE_SCORE,
    nameBonus,
    accessibilityBonus,
    sizePenalty,
    totalScore: score,
  });
  
  return score;
}

/**
 * Calculate priorities for multiple endpoints and sort them
 */
export function calculateAndSortPriorities(endpoints: Endpoint[]): Endpoint[] {
  logger.info('Calculating priorities for endpoints', { count: endpoints.length });
  
  // Calculate priority for each endpoint
  const endpointsWithPriority = endpoints.map(endpoint => ({
    ...endpoint,
    priorityScore: calculatePriority(endpoint),
  }));
  
  // Sort by priority score (descending)
  const sorted = endpointsWithPriority.sort((a, b) => b.priorityScore - a.priorityScore);
  
  // Log top priorities
  const top5 = sorted.slice(0, 5);
  logger.info('Top 5 priority endpoints:', {
    endpoints: top5.map(e => ({
      route: e.routePattern,
      score: e.priorityScore,
      requiresAuth: e.requiresAuth,
    })),
  });
  
  return sorted;
}

/**
 * Get top N priority endpoints
 */
export function getTopPriorityEndpoints(endpoints: Endpoint[], topN: number): Endpoint[] {
  const sorted = calculateAndSortPriorities(endpoints);
  return sorted.slice(0, topN);
}

/**
 * Filter endpoints by minimum priority score
 */
export function filterByMinimumPriority(endpoints: Endpoint[], minScore: number): Endpoint[] {
  const withPriority = endpoints.map(endpoint => ({
    ...endpoint,
    priorityScore: calculatePriority(endpoint),
  }));
  
  return withPriority.filter(e => e.priorityScore >= minScore);
}

/**
 * Get priority statistics
 */
export interface PriorityStats {
  total: number;
  highPriority: number;    // score >= 80
  mediumPriority: number;  // score >= 60
  lowPriority: number;     // score < 60
  averageScore: number;
  maxScore: number;
  minScore: number;
}

export function getPriorityStatistics(endpoints: Endpoint[]): PriorityStats {
  if (endpoints.length === 0) {
    return {
      total: 0,
      highPriority: 0,
      mediumPriority: 0,
      lowPriority: 0,
      averageScore: 0,
      maxScore: 0,
      minScore: 0,
    };
  }
  
  const scores = endpoints.map(e => e.priorityScore);
  const sum = scores.reduce((a, b) => a + b, 0);
  
  return {
    total: endpoints.length,
    highPriority: scores.filter(s => s >= 80).length,
    mediumPriority: scores.filter(s => s >= 60 && s < 80).length,
    lowPriority: scores.filter(s => s < 60).length,
    averageScore: sum / endpoints.length,
    maxScore: Math.max(...scores),
    minScore: Math.min(...scores),
  };
}
