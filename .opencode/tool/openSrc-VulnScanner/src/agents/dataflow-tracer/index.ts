/**
 * DataFlowTracer - Data flow analysis agent
 * 
 * Responsibilities:
 * - Execute precise data flow analysis
 * - Trace complete path from variable source to sink
 * - Identify sanitization and validation in paths
 * - Assess exploitability of data flow paths
 */

import type {
  DataFlowTracer,
  TraceRequest,
  DataFlowPath,
  SanitizationInfo,
  ValidationInfo,
  ExploitabilityScore,
  DataFlowStep,
} from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';
import { promises as fs } from 'fs';

const logger = createLogger('DataFlowTracer');

export class DataFlowTracerImpl implements DataFlowTracer {
  async traceDataFlow(request: TraceRequest): Promise<DataFlowPath> {
    logger.info('Tracing data flow', {
      source: request.sourceLocation.filePath,
      sink: request.sinkLocation.filePath,
      maxDepth: request.maxDepth || 10,
    });
    
    try {
      // Load source code
      const code = await fs.readFile(request.sourceLocation.filePath, 'utf-8');
      const lines = code.split('\n');
      
      // Simplified data flow tracing - trace variable usage
      const steps: DataFlowStep[] = [];
      const maxDepth = request.maxDepth || 10;
      
      // Start from source
      steps.push({
        type: 'assignment',
        location: request.sourceLocation,
        code: lines[request.sourceLocation.lineNumber - 1] || '',
        variable: request.sourceVariable,
      });
      
      // Trace through intermediate steps (simplified)
      const variablePattern = new RegExp(`\\b${request.sourceVariable}\\b`, 'g');
      
      for (let i = request.sourceLocation.lineNumber; i < request.sinkLocation.lineNumber && steps.length < maxDepth; i++) {
        const line = lines[i] || '';
        
        if (variablePattern.test(line)) {
          // Check if it's an assignment
          if (line.includes('=')) {
            steps.push({
              type: 'assignment',
              location: {
                filePath: request.sourceLocation.filePath,
                lineNumber: i + 1,
              },
              code: line.trim(),
              variable: request.sourceVariable,
            });
          }
          // Check if it's a function call
          else if (line.includes('(')) {
            steps.push({
              type: 'function_call',
              location: {
                filePath: request.sourceLocation.filePath,
                lineNumber: i + 1,
              },
              code: line.trim(),
              variable: request.sourceVariable,
            });
          }
        }
      }
      
      // Add sink as final step
      steps.push({
        type: 'function_call',
        location: request.sinkLocation,
        code: lines[request.sinkLocation.lineNumber - 1] || '',
        variable: request.sourceVariable,
      });
      
      const path: DataFlowPath = {
        source: request.sourceLocation,
        sink: request.sinkLocation,
        steps,
        hasSanitization: false,
        hasValidation: false,
        classification: 'POSSIBLE',
      };
      
      // Detect sanitization and validation
      const sanitizations = this.detectSanitization(path);
      const validations = this.detectValidation(path);
      
      path.hasSanitization = sanitizations.length > 0;
      path.hasValidation = validations.length > 0;
      
      // Classify based on protections
      if (!path.hasSanitization && !path.hasValidation) {
        path.classification = 'CONFIRMED';
      } else if (sanitizations.some(s => s.effectiveness === 'WEAK') || 
                 validations.some(v => v.effectiveness === 'WEAK')) {
        path.classification = 'LIKELY';
      } else {
        path.classification = 'POSSIBLE';
      }
      
      logger.info('Data flow traced', {
        steps: steps.length,
        hasSanitization: path.hasSanitization,
        hasValidation: path.hasValidation,
        classification: path.classification,
      });
      
      return path;
    } catch (error) {
      logger.error('Data flow tracing failed', error as Error);
      
      // Return minimal path on error
      return {
        source: request.sourceLocation,
        sink: request.sinkLocation,
        steps: [],
        hasSanitization: false,
        hasValidation: false,
        classification: 'POSSIBLE',
      };
    }
  }

  detectSanitization(path: DataFlowPath): SanitizationInfo[] {
    logger.debug('Detecting sanitization in path');
    
    const sanitizations: SanitizationInfo[] = [];
    
    // Known sanitization functions
    const sanitizationPatterns = [
      { pattern: /escape/i, effectiveness: 'STRONG' as const },
      { pattern: /sanitize/i, effectiveness: 'STRONG' as const },
      { pattern: /clean/i, effectiveness: 'WEAK' as const },
      { pattern: /filter/i, effectiveness: 'WEAK' as const },
      { pattern: /strip/i, effectiveness: 'WEAK' as const },
      { pattern: /encode/i, effectiveness: 'STRONG' as const },
    ];
    
    for (const step of path.steps) {
      for (const { pattern, effectiveness } of sanitizationPatterns) {
        if (pattern.test(step.code)) {
          const match = step.code.match(/(\w+)\s*\(/);
          sanitizations.push({
            functionName: match ? match[1] : 'unknown',
            location: step.location,
            effectiveness,
          });
        }
      }
    }
    
    return sanitizations;
  }

  detectValidation(path: DataFlowPath): ValidationInfo[] {
    logger.debug('Detecting validation in path');
    
    const validations: ValidationInfo[] = [];
    
    // Validation patterns
    const validationPatterns = [
      { pattern: /typeof\s+\w+\s*===/, type: 'type_check' as const, effectiveness: 'STRONG' as const },
      { pattern: /instanceof/, type: 'type_check' as const, effectiveness: 'STRONG' as const },
      { pattern: /\w+\s*>\s*\d+|\w+\s*<\s*\d+/, type: 'range_check' as const, effectiveness: 'WEAK' as const },
      { pattern: /\.test\(|\.match\(/, type: 'regex' as const, effectiveness: 'STRONG' as const },
      { pattern: /includes\(|indexOf\(/, type: 'whitelist' as const, effectiveness: 'WEAK' as const },
    ];
    
    for (const step of path.steps) {
      for (const { pattern, type, effectiveness } of validationPatterns) {
        if (pattern.test(step.code)) {
          validations.push({
            type,
            location: step.location,
            effectiveness,
          });
        }
      }
    }
    
    return validations;
  }

  assessExploitability(path: DataFlowPath): ExploitabilityScore {
    logger.debug('Assessing exploitability');
    
    let score = 100; // Start with maximum exploitability
    
    // Reduce score based on protections
    if (path.hasSanitization) {
      score -= 40;
    }
    
    if (path.hasValidation) {
      score -= 30;
    }
    
    // Adjust based on path complexity
    if (path.steps.length > 10) {
      score -= 10;
    }
    
    return Math.max(0, score);
  }
}
