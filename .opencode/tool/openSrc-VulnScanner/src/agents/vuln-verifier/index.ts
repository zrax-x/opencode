/**
 * VulnVerifier - Vulnerability verification agent
 * 
 * Responsibilities:
 * - Independently verify discovered vulnerabilities
 * - Use different analysis methods and heuristic rules
 * - Assess effectiveness of sanitization and validation
 * - Return confidence assessment
 */

import type {
  VulnVerifier,
  VerificationResult,
  Finding,
  DataFlowPath,
  SanitizationInfo,
  ValidationInfo,
  VulnerabilityType,
  Severity,
} from '../../types/index.js';
import { DataFlowTracerImpl } from '../dataflow-tracer/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('VulnVerifier');

export class VulnVerifierImpl implements VulnVerifier {
  private dataFlowTracer = new DataFlowTracerImpl();

  async verifyVulnerability(finding: Finding): Promise<VerificationResult> {
    logger.info('Verifying vulnerability', {
      type: finding.vulnerabilityType,
      location: finding.location.filePath,
    });
    
    try {
      // Re-analyze the data flow with different heuristics
      const reanalyzedPath = await this.reanalyzeDataFlow(finding.dataFlowPath);
      
      // Check for sanitization
      const sanitizations = this.dataFlowTracer.detectSanitization(reanalyzedPath);
      const hasEffectiveSanitization = sanitizations.some(s => 
        this.assessSanitization(s, finding.vulnerabilityType)
      );
      
      // Check for validation
      const validations = this.dataFlowTracer.detectValidation(reanalyzedPath);
      const hasEffectiveValidation = validations.some(v => 
        this.assessValidation(v, finding.vulnerabilityType)
      );
      
      // Determine confidence
      let confidence: 'CONFIRMED' | 'UNCERTAIN' | 'REJECTED';
      let reasoning: string;
      const evidence: string[] = [];
      
      if (hasEffectiveSanitization || hasEffectiveValidation) {
        confidence = 'REJECTED';
        reasoning = 'Effective sanitization or validation detected in data flow path';
        if (hasEffectiveSanitization) {
          evidence.push(`Found ${sanitizations.length} sanitization function(s)`);
        }
        if (hasEffectiveValidation) {
          evidence.push(`Found ${validations.length} validation check(s)`);
        }
      } else if (reanalyzedPath.steps.length === 0) {
        confidence = 'UNCERTAIN';
        reasoning = 'Unable to trace complete data flow path';
      } else if (reanalyzedPath.classification === 'CONFIRMED') {
        confidence = 'CONFIRMED';
        reasoning = 'Direct data flow from user input to dangerous sink without protection';
        evidence.push(`Data flow path has ${reanalyzedPath.steps.length} steps`);
      } else {
        confidence = 'UNCERTAIN';
        reasoning = 'Data flow path exists but exploitability is unclear';
        evidence.push(`Path classification: ${reanalyzedPath.classification}`);
      }
      
      logger.info('Verification completed', {
        type: finding.vulnerabilityType,
        confidence,
      });
      
      return {
        originalFinding: finding,
        confidence,
        reasoning,
        additionalEvidence: evidence,
      };
    } catch (error) {
      logger.error('Verification failed', error as Error);
      
      // Default to UNCERTAIN on error
      return {
        originalFinding: finding,
        confidence: 'UNCERTAIN',
        reasoning: `Verification failed: ${(error as Error).message}`,
      };
    }
  }

  async reanalyzeDataFlow(path: DataFlowPath): Promise<DataFlowPath> {
    logger.debug('Re-analyzing data flow');
    
    // For now, return the same path
    // In a full implementation, this would use different analysis techniques
    return path;
  }

  assessSanitization(
    sanitization: SanitizationInfo,
    vulnType: VulnerabilityType
  ): boolean {
    logger.debug('Assessing sanitization effectiveness', {
      function: sanitization.functionName,
      vulnType,
    });
    
    // Only STRONG sanitization is considered effective
    if (sanitization.effectiveness !== 'STRONG') {
      return false;
    }
    
    // Check if sanitization is appropriate for vulnerability type
    const effectiveSanitizations: Record<VulnerabilityType, string[]> = {
      RCE: ['escape', 'sanitize', 'encode'],
      COMMAND_INJECTION: ['escape', 'sanitize', 'shellEscape'],
      AUTH_BYPASS: ['verify', 'validate', 'authenticate'],
      ARBITRARY_FILE_READ: ['normalize', 'sanitize', 'resolve'],
      PATH_TRAVERSAL: ['normalize', 'resolve', 'sanitize'],
    };
    
    const effective = effectiveSanitizations[vulnType] || [];
    return effective.some(pattern => 
      sanitization.functionName.toLowerCase().includes(pattern.toLowerCase())
    );
  }

  assessValidation(
    validation: ValidationInfo,
    vulnType: VulnerabilityType
  ): boolean {
    logger.debug('Assessing validation effectiveness', {
      type: validation.type,
      vulnType,
    });
    
    // Only STRONG validation is considered effective
    if (validation.effectiveness !== 'STRONG') {
      return false;
    }
    
    // Check if validation type is appropriate for vulnerability type
    const effectiveValidations: Record<VulnerabilityType, ValidationInfo['type'][]> = {
      RCE: ['type_check', 'regex', 'whitelist'],
      COMMAND_INJECTION: ['regex', 'whitelist'],
      AUTH_BYPASS: ['type_check'],
      ARBITRARY_FILE_READ: ['regex', 'whitelist'],
      PATH_TRAVERSAL: ['regex', 'whitelist'],
    };
    
    const effective = effectiveValidations[vulnType] || [];
    return effective.includes(validation.type);
  }
}
