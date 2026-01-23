/**
 * EndpointAnalyzer - Endpoint analysis agent
 * 
 * Responsibilities:
 * - Deep analysis of individual endpoint security vulnerabilities
 * - Identify all user input sources
 * - Call DataFlowTracer to trace data flows
 * - Identify dangerous function calls (command execution, file operations, etc.)
 * - Generate detailed vulnerability reports
 */

import type {
  EndpointAnalyzer,
  AnalysisTask,
  AnalysisResult,
  InputSource,
  DangerousSink,
  Endpoint,
  AuthInfo,
  Finding,
  VulnerabilityType,
  Severity,
} from '../../types/index.js';
import { DataFlowTracerImpl } from '../dataflow-tracer/index.js';
import { createLogger } from '../../utils/logger.js';
import { promises as fs } from 'fs';

const logger = createLogger('EndpointAnalyzer');

export class EndpointAnalyzerImpl implements EndpointAnalyzer {
  private dataFlowTracer = new DataFlowTracerImpl();

  async analyzeEndpoint(task: AnalysisTask): Promise<AnalysisResult> {
    const startTime = Date.now();
    logger.info('Analyzing endpoint', {
      route: task.endpoint.routePattern,
      filePath: task.endpoint.filePath,
    });
    
    try {
      // Load code
      const code = await this.loadCode(task.endpoint.filePath);
      
      // Identify input sources
      const inputSources = this.identifyInputSources(task.endpoint);
      
      // Identify dangerous sinks
      const dangerousSinks = this.identifyDangerousSinks(code);
      
      // Detect auth mechanism
      const authInfo = this.detectAuthMechanism(task.endpoint);
      
      // Generate findings by analyzing data flows
      const findings: Finding[] = [];
      
      for (const sink of dangerousSinks) {
        for (const source of inputSources) {
          try {
            // Trace data flow from source to sink
            const dataFlowPath = await this.dataFlowTracer.traceDataFlow({
              sourceLocation: source.location,
              sinkLocation: sink.location,
              sourceVariable: source.name,
              sinkFunction: sink.functionName,
              maxDepth: 10,
            });
            
            // If path exists and is exploitable, create finding
            if (dataFlowPath.steps.length > 0) {
              const severity = this.calculateSeverity(
                sink.type,
                authInfo.requiresAuth,
                dataFlowPath
              );
              
              findings.push({
                vulnerabilityType: sink.type,
                severity,
                cweId: sink.cweId,
                location: sink.location,
                dataFlowPath,
                codeSnippet: this.extractCodeSnippet(code, sink.location.lineNumber),
                confidence: 'INITIAL',
              });
            }
          } catch (error) {
            logger.debug('Data flow trace failed', {
              source: source.name,
              sink: sink.functionName,
              error: error as Error,
            });
          }
        }
      }
      
      const analysisTime = Date.now() - startTime;
      
      logger.info('Analysis completed', {
        route: task.endpoint.routePattern,
        findings: findings.length,
        time: analysisTime,
      });
      
      return {
        endpoint: task.endpoint,
        findings,
        authInfo,
        analysisTime,
      };
    } catch (error) {
      logger.error('Analysis failed', error as Error);
      
      return {
        endpoint: task.endpoint,
        findings: [],
        authInfo: { requiresAuth: task.endpoint.requiresAuth },
        analysisTime: Date.now() - startTime,
        errors: [(error as Error).message],
      };
    }
  }

  private async loadCode(filePath: string): Promise<string> {
    return await fs.readFile(filePath, 'utf-8');
  }

  identifyInputSources(endpoint: Endpoint): InputSource[] {
    logger.debug('Identifying input sources', { endpoint: endpoint.routePattern });
    
    // Basic input source identification based on common patterns
    const sources: InputSource[] = [];
    
    // Add common input sources based on framework
    const commonSources = [
      { type: 'query' as const, name: 'query' },
      { type: 'body' as const, name: 'body' },
      { type: 'header' as const, name: 'headers' },
      { type: 'cookie' as const, name: 'cookies' },
      { type: 'path' as const, name: 'params' },
    ];
    
    for (const source of commonSources) {
      sources.push({
        type: source.type,
        name: source.name,
        location: {
          filePath: endpoint.filePath,
          lineNumber: endpoint.lineNumber,
          functionName: endpoint.handlerFunction,
        },
      });
    }
    
    return sources;
  }

  identifyDangerousSinks(code: string): DangerousSink[] {
    logger.debug('Identifying dangerous sinks');
    
    const sinks: DangerousSink[] = [];
    const lines = code.split('\n');
    
    // Define dangerous patterns for each vulnerability type
    const patterns: Array<{
      regex: RegExp;
      type: VulnerabilityType;
      cweId: number;
    }> = [
      // RCE patterns
      { regex: /\beval\s*\(/i, type: 'RCE', cweId: 94 },
      { regex: /\bFunction\s*\(/i, type: 'RCE', cweId: 94 },
      { regex: /\bvm\.runInNewContext\s*\(/i, type: 'RCE', cweId: 94 },
      { regex: /\bvm\.runInThisContext\s*\(/i, type: 'RCE', cweId: 94 },
      
      // Command Injection patterns
      { regex: /\bexec\s*\(/i, type: 'COMMAND_INJECTION', cweId: 78 },
      { regex: /\bspawn\s*\(/i, type: 'COMMAND_INJECTION', cweId: 78 },
      { regex: /\bexecSync\s*\(/i, type: 'COMMAND_INJECTION', cweId: 78 },
      { regex: /\bchild_process\./i, type: 'COMMAND_INJECTION', cweId: 78 },
      { regex: /\bos\.system\s*\(/i, type: 'COMMAND_INJECTION', cweId: 78 },
      { regex: /\bsubprocess\./i, type: 'COMMAND_INJECTION', cweId: 78 },
      
      // Arbitrary File Read patterns
      { regex: /\breadFile\s*\(/i, type: 'ARBITRARY_FILE_READ', cweId: 22 },
      { regex: /\bfs\.read\s*\(/i, type: 'ARBITRARY_FILE_READ', cweId: 22 },
      { regex: /\bopen\s*\(/i, type: 'ARBITRARY_FILE_READ', cweId: 22 },
      { regex: /\bfile_get_contents\s*\(/i, type: 'ARBITRARY_FILE_READ', cweId: 22 },
      
      // Path Traversal patterns
      { regex: /\bpath\.join\s*\(/i, type: 'PATH_TRAVERSAL', cweId: 22 },
      { regex: /\bpath\.resolve\s*\(/i, type: 'PATH_TRAVERSAL', cweId: 22 },
      { regex: /\bos\.path\.join\s*\(/i, type: 'PATH_TRAVERSAL', cweId: 22 },
    ];
    
    lines.forEach((line, index) => {
      for (const pattern of patterns) {
        const match = line.match(pattern.regex);
        if (match) {
          const functionName = match[0].replace(/\s*\($/, '');
          sinks.push({
            type: pattern.type,
            functionName,
            location: {
              filePath: '',
              lineNumber: index + 1,
            },
            cweId: pattern.cweId,
          });
        }
      }
    });
    
    return sinks;
  }

  detectAuthMechanism(endpoint: Endpoint): AuthInfo {
    logger.debug('Detecting auth mechanism', { endpoint: endpoint.routePattern });
    
    return {
      requiresAuth: endpoint.requiresAuth,
      authType: endpoint.requiresAuth ? 'JWT' : 'NONE',
    };
  }

  private calculateSeverity(
    vulnType: VulnerabilityType,
    requiresAuth: boolean,
    dataFlowPath: any
  ): Severity {
    // Base severity by vulnerability type
    let severity: Severity;
    
    switch (vulnType) {
      case 'RCE':
        severity = 'CRITICAL';
        break;
      case 'COMMAND_INJECTION':
        severity = 'HIGH';
        break;
      case 'AUTH_BYPASS':
        severity = 'MEDIUM';
        break;
      case 'ARBITRARY_FILE_READ':
        severity = 'MEDIUM';
        break;
      case 'PATH_TRAVERSAL':
        severity = 'MEDIUM';
        break;
    }
    
    // Adjust based on authentication
    if (!requiresAuth && severity === 'HIGH') {
      severity = 'CRITICAL';
    }
    
    // Adjust based on sanitization/validation
    if (dataFlowPath.hasSanitization || dataFlowPath.hasValidation) {
      if (severity === 'CRITICAL') severity = 'HIGH';
      else if (severity === 'HIGH') severity = 'MEDIUM';
      else if (severity === 'MEDIUM') severity = 'LOW';
    }
    
    return severity;
  }

  private extractCodeSnippet(code: string, lineNumber: number): string {
    const lines = code.split('\n');
    const start = Math.max(0, lineNumber - 2);
    const end = Math.min(lines.length, lineNumber + 2);
    return lines.slice(start, end).join('\n');
  }
}
