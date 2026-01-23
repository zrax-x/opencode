/**
 * Authentication Mechanism Detection Module
 * 
 * Identifies authentication and authorization mechanisms for endpoints
 * Detects middleware, decorators, JWT, Session, API keys, OAuth, RBAC
 */

import * as fs from 'fs/promises';
import type { Endpoint, AuthInfo } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('AuthDetection');

/**
 * Authentication patterns for different frameworks
 */
interface AuthPattern {
  type: 'JWT' | 'SESSION' | 'API_KEY' | 'OAUTH' | 'BASIC' | 'NONE';
  pattern: RegExp;
  contextLines?: number; // Number of lines to check before/after
}

/**
 * Common authentication middleware patterns
 */
const AUTH_MIDDLEWARE_PATTERNS: AuthPattern[] = [
  // JWT patterns
  { type: 'JWT', pattern: /jwt\.verify|verifyToken|validateJWT|checkJWT/i },
  { type: 'JWT', pattern: /@jwt_required|@login_required.*jwt/i },
  { type: 'JWT', pattern: /passport\.authenticate.*jwt/i },
  { type: 'JWT', pattern: /Authorization.*Bearer/i },
  
  // Session patterns
  { type: 'SESSION', pattern: /session\.get|req\.session|express-session/i },
  { type: 'SESSION', pattern: /@login_required|@authenticated/i },
  { type: 'SESSION', pattern: /checkSession|validateSession|requireSession/i },
  
  // API Key patterns
  { type: 'API_KEY', pattern: /api[_-]?key|x-api-key/i },
  { type: 'API_KEY', pattern: /validateApiKey|checkApiKey|requireApiKey/i },
  
  // OAuth patterns
  { type: 'OAUTH', pattern: /oauth|passport\.authenticate.*oauth/i },
  { type: 'OAUTH', pattern: /google\.auth|github\.auth|facebook\.auth/i },
  
  // Basic Auth patterns
  { type: 'BASIC', pattern: /basic.*auth|Authorization.*Basic/i },
  { type: 'BASIC', pattern: /http\.BasicAuth|basicAuth/i },
];

/**
 * Middleware decorator patterns by language/framework
 */
const MIDDLEWARE_DECORATORS: Record<string, RegExp[]> = {
  Python: [
    /@login_required/,
    /@jwt_required/,
    /@auth\.login_required/,
    /@requires_auth/,
    /@authenticated/,
  ],
  JavaScript: [
    /\.use\s*\(\s*auth/i,
    /\.use\s*\(\s*authenticate/i,
    /\.use\s*\(\s*requireAuth/i,
    /middleware:\s*\[.*auth.*\]/i,
  ],
  Java: [
    /@PreAuthorize/,
    /@Secured/,
    /@RolesAllowed/,
    /@Authenticated/,
  ],
  Go: [
    /AuthMiddleware/,
    /RequireAuth/,
    /\.Use\(.*[Aa]uth.*\)/,
  ],
  Rust: [
    /#\[guard\(/,
    /#\[auth\(/,
    /\.guard\(/,
  ],
};

/**
 * RBAC and permission check patterns
 */
const RBAC_PATTERNS: RegExp[] = [
  /hasRole|checkRole|requireRole/i,
  /hasPermission|checkPermission|requirePermission/i,
  /can\(|ability\.|authorize\(/i,
  /@PreAuthorize.*hasRole/,
  /@RolesAllowed/,
  /if.*user\.role|if.*user\.permissions/i,
];

/**
 * Read file content around a specific line
 */
async function readFileContext(
  filePath: string,
  lineNumber: number,
  contextLines: number = 20
): Promise<string> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - contextLines);
    const end = Math.min(lines.length, lineNumber + contextLines);
    return lines.slice(start, end).join('\n');
  } catch (error) {
    logger.warn('Failed to read file context', { filePath, error: (error as Error).message });
    return '';
  }
}

/**
 * Detect authentication type from code context
 */
function detectAuthType(context: string): AuthInfo['authType'] {
  for (const pattern of AUTH_MIDDLEWARE_PATTERNS) {
    if (pattern.pattern.test(context)) {
      return pattern.type;
    }
  }
  return 'NONE';
}

/**
 * Extract middleware names from code
 */
function extractMiddleware(context: string, language: string): string[] {
  const middleware: string[] = [];
  
  // Language-specific middleware extraction
  if (language === 'Python') {
    // Flask/FastAPI decorators: @app.route(...) @login_required
    const decoratorMatches = context.matchAll(/@(\w+)/g);
    for (const match of decoratorMatches) {
      if (match[1] !== 'app' && match[1] !== 'route') {
        middleware.push(match[1]);
      }
    }
  } else if (language === 'JavaScript' || language === 'TypeScript') {
    // Express middleware: app.use(authMiddleware)
    const useMatches = context.matchAll(/\.use\s*\(\s*(\w+)/g);
    for (const match of useMatches) {
      middleware.push(match[1]);
    }
    
    // Middleware array: [auth, validate]
    const arrayMatch = context.match(/middleware:\s*\[(.*?)\]/);
    if (arrayMatch) {
      const items = arrayMatch[1].split(',').map(s => s.trim());
      middleware.push(...items);
    }
  } else if (language === 'Java') {
    // Spring Security annotations
    const annotationMatches = context.matchAll(/@(\w+)/g);
    for (const match of annotationMatches) {
      if (['PreAuthorize', 'Secured', 'RolesAllowed', 'Authenticated'].includes(match[1])) {
        middleware.push(match[1]);
      }
    }
  }
  
  return middleware;
}

/**
 * Detect RBAC checks in code
 */
function detectRBACChecks(context: string): string[] {
  const checks: string[] = [];
  
  for (const pattern of RBAC_PATTERNS) {
    const matches = context.matchAll(new RegExp(pattern.source, 'gi'));
    for (const match of matches) {
      checks.push(match[0]);
    }
  }
  
  return checks;
}

/**
 * Check if endpoint has authentication middleware
 */
function hasAuthMiddleware(context: string, language: string): boolean {
  const patterns = MIDDLEWARE_DECORATORS[language] || [];
  
  for (const pattern of patterns) {
    if (pattern.test(context)) {
      return true;
    }
  }
  
  // Check general auth patterns
  for (const pattern of AUTH_MIDDLEWARE_PATTERNS) {
    if (pattern.pattern.test(context)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Detect authentication mechanism for an endpoint
 */
export async function detectAuthMechanism(endpoint: Endpoint): Promise<AuthInfo> {
  logger.debug('Detecting auth mechanism', { 
    endpoint: endpoint.routePattern,
    filePath: endpoint.filePath 
  });

  try {
    // Read code context around the endpoint
    const context = await readFileContext(endpoint.filePath, endpoint.lineNumber, 30);
    
    // Check if endpoint has authentication
    const requiresAuth = hasAuthMiddleware(context, endpoint.language);
    
    // Detect authentication type
    const authType = requiresAuth ? detectAuthType(context) : 'NONE';
    
    // Extract middleware names
    const authMiddleware = extractMiddleware(context, endpoint.language);
    
    // Detect RBAC checks
    const rbacChecks = detectRBACChecks(context);
    
    const authInfo: AuthInfo = {
      requiresAuth,
      authType,
      authMiddleware: authMiddleware.length > 0 ? authMiddleware : undefined,
      rbacChecks: rbacChecks.length > 0 ? rbacChecks : undefined,
    };
    
    logger.debug('Auth detection result', { 
      endpoint: endpoint.routePattern,
      requiresAuth,
      authType 
    });
    
    return authInfo;
  } catch (error) {
    logger.error('Failed to detect auth mechanism', error as Error, {
      endpoint: endpoint.routePattern,
      filePath: endpoint.filePath,
    });
    
    // Return default (no auth) on error
    return {
      requiresAuth: false,
      authType: 'NONE',
    };
  }
}

/**
 * Batch detect authentication for multiple endpoints
 */
export async function detectAuthForEndpoints(endpoints: Endpoint[]): Promise<Map<Endpoint, AuthInfo>> {
  logger.info('Detecting auth for endpoints', { count: endpoints.length });
  
  const authMap = new Map<Endpoint, AuthInfo>();
  
  for (const endpoint of endpoints) {
    const authInfo = await detectAuthMechanism(endpoint);
    authMap.set(endpoint, authInfo);
  }
  
  const authCount = Array.from(authMap.values()).filter(a => a.requiresAuth).length;
  logger.info(`Found ${authCount} authenticated endpoints out of ${endpoints.length}`);
  
  return authMap;
}

/**
 * Update endpoints with authentication information
 */
export async function enrichEndpointsWithAuth(endpoints: Endpoint[]): Promise<Endpoint[]> {
  const authMap = await detectAuthForEndpoints(endpoints);
  
  return endpoints.map(endpoint => {
    const authInfo = authMap.get(endpoint);
    return {
      ...endpoint,
      requiresAuth: authInfo?.requiresAuth || false,
    };
  });
}
