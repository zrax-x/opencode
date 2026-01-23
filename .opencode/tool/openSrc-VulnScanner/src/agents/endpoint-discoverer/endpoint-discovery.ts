/**
 * Endpoint Discovery Module
 * 
 * Discovers all remote-accessible endpoints in a codebase
 * Supports multiple languages and frameworks
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { Endpoint } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('EndpointDiscovery');

export interface EndpointPattern {
  language: string;
  framework: string;
  pattern: RegExp;
  extract: (match: RegExpMatchArray, filePath: string, lineNumber: number) => Partial<Endpoint> | null;
}

/**
 * Python framework patterns
 */
const PYTHON_PATTERNS: EndpointPattern[] = [
  // Flask: @app.route('/path', methods=['GET', 'POST'])
  {
    language: 'Python',
    framework: 'Flask',
    pattern: /@app\.route\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]+)\])?\s*\)/,
    extract: (match, filePath, lineNumber) => {
      const route = match[1];
      const methods = match[2]?.split(',').map(m => m.trim().replace(/['"]/g, '')) || ['GET'];
      return {
        routePattern: route,
        httpMethod: methods[0],
        framework: 'Flask',
        language: 'Python',
        filePath,
        lineNumber,
      };
    },
  },
  // Django: path('api/users/<int:user_id>/', views.get_user)
  {
    language: 'Python',
    framework: 'Django',
    pattern: /path\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: match[1],
      handlerFunction: match[2].trim(),
      framework: 'Django',
      language: 'Python',
      filePath,
      lineNumber,
    }),
  },
  // FastAPI: @app.get("/api/users/{user_id}")
  {
    language: 'Python',
    framework: 'FastAPI',
    pattern: /@app\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'FastAPI',
      language: 'Python',
      filePath,
      lineNumber,
    }),
  },
];

/**
 * Node.js framework patterns
 */
const NODEJS_PATTERNS: EndpointPattern[] = [
  // Express: app.get('/api/users/:userId', ...)
  {
    language: 'JavaScript',
    framework: 'Express',
    pattern: /app\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]\s*,/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Express',
      language: 'JavaScript',
      filePath,
      lineNumber,
    }),
  },
  // Koa: router.get('/api/users/:userId', ...)
  {
    language: 'JavaScript',
    framework: 'Koa',
    pattern: /router\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Koa',
      language: 'JavaScript',
      filePath,
      lineNumber,
    }),
  },
  // Fastify: fastify.get('/api/users/:userId', ...)
  {
    language: 'JavaScript',
    framework: 'Fastify',
    pattern: /fastify\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Fastify',
      language: 'JavaScript',
      filePath,
      lineNumber,
    }),
  },
];

/**
 * Java framework patterns
 */
const JAVA_PATTERNS: EndpointPattern[] = [
  // Spring Boot: @GetMapping("/api/users/{userId}")
  {
    language: 'Java',
    framework: 'Spring Boot',
    pattern: /@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*"([^"]+)"\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Spring Boot',
      language: 'Java',
      filePath,
      lineNumber,
    }),
  },
  // JAX-RS: @Path("/api/users") @GET
  {
    language: 'Java',
    framework: 'JAX-RS',
    pattern: /@Path\s*\(\s*"([^"]+)"\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: match[1],
      framework: 'JAX-RS',
      language: 'Java',
      filePath,
      lineNumber,
    }),
  },
];

/**
 * Go framework patterns
 */
const GO_PATTERNS: EndpointPattern[] = [
  // net/http: http.HandleFunc("/api/users/", handler)
  {
    language: 'Go',
    framework: 'net/http',
    pattern: /http\.HandleFunc\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: match[1],
      handlerFunction: match[2],
      framework: 'net/http',
      language: 'Go',
      filePath,
      lineNumber,
    }),
  },
  // Gin: r.GET("/api/users/:userId", handler)
  {
    language: 'Go',
    framework: 'Gin',
    pattern: /r\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1],
      routePattern: match[2],
      handlerFunction: match[3],
      framework: 'Gin',
      language: 'Go',
      filePath,
      lineNumber,
    }),
  },
  // Echo: e.GET("/api/users/:userId", handler)
  {
    language: 'Go',
    framework: 'Echo',
    pattern: /e\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1],
      routePattern: match[2],
      handlerFunction: match[3],
      framework: 'Echo',
      language: 'Go',
      filePath,
      lineNumber,
    }),
  },
];

/**
 * Rust framework patterns
 */
const RUST_PATTERNS: EndpointPattern[] = [
  // Actix-web: #[get("/api/users/{user_id}")]
  {
    language: 'Rust',
    framework: 'Actix-web',
    pattern: /#\[(get|post|put|delete|patch)\s*\(\s*"([^"]+)"\s*\)\]/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Actix-web',
      language: 'Rust',
      filePath,
      lineNumber,
    }),
  },
  // Rocket: #[get("/api/users/<user_id>")]
  {
    language: 'Rust',
    framework: 'Rocket',
    pattern: /#\[(get|post|put|delete|patch)\s*\(\s*"([^"]+)"\s*\)\]/,
    extract: (match, filePath, lineNumber) => ({
      httpMethod: match[1].toUpperCase(),
      routePattern: match[2],
      framework: 'Rocket',
      language: 'Rust',
      filePath,
      lineNumber,
    }),
  },
];

/**
 * C/C++ network function patterns
 */
const C_CPP_PATTERNS: EndpointPattern[] = [
  // Socket API: bind(sockfd, ...)
  {
    language: 'C/C++',
    framework: 'Socket API',
    pattern: /bind\s*\(\s*(\w+)\s*,/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: 'socket_bind',
      handlerFunction: match[1],
      framework: 'Socket API',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // HTTP library: evhtp_set_cb(htp, "/api/users", callback, NULL)
  {
    language: 'C/C++',
    framework: 'evhtp',
    pattern: /evhtp_set_cb\s*\(\s*\w+\s*,\s*"([^"]+)"\s*,\s*(\w+)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: match[1],
      handlerFunction: match[2],
      framework: 'evhtp',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc: AddBuiltinServices() - registers internal services
  {
    language: 'C/C++',
    framework: 'brpc',
    pattern: /AddBuiltinServices\s*\(\s*\)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: '/builtin_services',
      handlerFunction: 'AddBuiltinServices',
      framework: 'brpc',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc: AddService(&service, ...) - registers RPC service
  {
    language: 'C/C++',
    framework: 'brpc',
    pattern: /AddService\s*\(\s*&(\w+)/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: `/${match[1]}`,
      handlerFunction: match[1],
      framework: 'brpc',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc RPC method: void ServiceName::MethodName(RpcController* controller, ...)
  {
    language: 'C/C++',
    framework: 'brpc',
    pattern: /void\s+(\w+)::(\w+)\s*\(\s*(?:google::protobuf::)?RpcController\s*\*/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: `/${match[1]}/${match[2]}`,
      handlerFunction: `${match[1]}::${match[2]}`,
      framework: 'brpc',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc RPC method: void ServiceName::MethodName(Controller* controller, ...)
  {
    language: 'C/C++',
    framework: 'brpc',
    pattern: /void\s+(\w+)::(\w+)\s*\(\s*(?:brpc::)?Controller\s*\*/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: `/${match[1]}/${match[2]}`,
      handlerFunction: `${match[1]}::${match[2]}`,
      framework: 'brpc',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc builtin service methods (heap, pprof, status, etc.)
  {
    language: 'C/C++',
    framework: 'brpc-builtin',
    pattern: /void\s+(Heap|Pprof|Status|Vars|Flags|Threads|Connections|BadMethod|Health|Version|Rpcz|Hotspots|Contention|Index|List)\s*\(\s*(?:google::protobuf::)?RpcController/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: `/${match[1].toLowerCase()}`,
      handlerFunction: match[1],
      framework: 'brpc-builtin',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
  // brpc HTTP handler: void OnXxx(HttpRequest& request, HttpResponse& response)
  {
    language: 'C/C++',
    framework: 'brpc-http',
    pattern: /void\s+(\w+)\s*\(\s*(?:brpc::)?HttpRequest\s*&/,
    extract: (match, filePath, lineNumber) => ({
      routePattern: `/${match[1]}`,
      handlerFunction: match[1],
      framework: 'brpc-http',
      language: 'C/C++',
      filePath,
      lineNumber,
    }),
  },
];

// Combine all patterns
const ALL_PATTERNS: EndpointPattern[] = [
  ...PYTHON_PATTERNS,
  ...NODEJS_PATTERNS,
  ...JAVA_PATTERNS,
  ...GO_PATTERNS,
  ...RUST_PATTERNS,
  ...C_CPP_PATTERNS,
];

/**
 * File extension to language mapping
 */
const EXTENSION_TO_LANGUAGE: Record<string, string> = {
  '.py': 'Python',
  '.js': 'JavaScript',
  '.ts': 'TypeScript',
  '.java': 'Java',
  '.go': 'Go',
  '.rs': 'Rust',
  '.c': 'C',
  '.cpp': 'C++',
  '.cc': 'C++',
  '.h': 'C/C++',
  '.hpp': 'C++',
};

/**
 * Discover endpoints in a single file
 */
async function discoverEndpointsInFile(filePath: string): Promise<Partial<Endpoint>[]> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    const ext = path.extname(filePath);
    const language = EXTENSION_TO_LANGUAGE[ext];

    if (!language) {
      return [];
    }

    const endpoints: Partial<Endpoint>[] = [];

    // Filter patterns by language
    const relevantPatterns = ALL_PATTERNS.filter(p => 
      p.language === language || 
      (language === 'TypeScript' && p.language === 'JavaScript')
    );

    // Search for patterns in each line
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      for (const pattern of relevantPatterns) {
        const match = line.match(pattern.pattern);
        if (match) {
          const endpoint = pattern.extract(match, filePath, lineNumber);
          if (endpoint) {
            // Try to extract handler function name from next few lines
            if (!endpoint.handlerFunction) {
              const nextLines = lines.slice(i + 1, i + 5).join('\n');
              const funcMatch = nextLines.match(/(?:def|function|fn|func)\s+(\w+)/);
              if (funcMatch) {
                endpoint.handlerFunction = funcMatch[1];
              }
            }
            endpoints.push(endpoint);
          }
        }
      }
    }

    return endpoints;
  } catch (error) {
    logger.error('Failed to discover endpoints in file', error as Error, { filePath });
    return [];
  }
}

/**
 * Recursively find all source files in a directory
 */
async function findSourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Skip common directories to ignore
      if (entry.isDirectory()) {
        const skipDirs = ['node_modules', '.git', 'dist', 'build', 'target', '__pycache__', 'venv'];
        if (skipDirs.includes(entry.name)) {
          continue;
        }
        const subFiles = await findSourceFiles(fullPath);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (EXTENSION_TO_LANGUAGE[ext]) {
          files.push(fullPath);
        }
      }
    }
  } catch (error) {
    logger.warn('Failed to read directory', { dir, error: (error as Error).message });
  }

  return files;
}

/**
 * Main endpoint discovery function
 */
export async function discoverEndpoints(codebasePath: string): Promise<Endpoint[]> {
  logger.info('Starting endpoint discovery', { codebasePath });

  const sourceFiles = await findSourceFiles(codebasePath);
  logger.info(`Found ${sourceFiles.length} source files`);

  const allEndpoints: Partial<Endpoint>[] = [];

  for (const file of sourceFiles) {
    const endpoints = await discoverEndpointsInFile(file);
    allEndpoints.push(...endpoints);
  }

  // Convert partial endpoints to full endpoints with defaults
  const completeEndpoints: Endpoint[] = allEndpoints.map(ep => ({
    filePath: ep.filePath || '',
    lineNumber: ep.lineNumber || 0,
    httpMethod: ep.httpMethod || 'UNKNOWN',
    routePattern: ep.routePattern || '',
    handlerFunction: ep.handlerFunction || 'unknown',
    framework: ep.framework || 'Unknown',
    language: ep.language || 'Unknown',
    requiresAuth: false, // Will be determined later
    priorityScore: 0, // Will be calculated later
  }));

  logger.info(`Discovered ${completeEndpoints.length} endpoints`);

  return completeEndpoints;
}
