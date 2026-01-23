/**
 * OpenSrc-VulnScanner - Main entry point
 * 
 * Multi-agent vulnerability scanner for open source codebases
 * 
 * Architecture (5 Agents):
 * - OpenSrcCoordinator: Pure orchestrator, dispatches tasks
 * - EndpointDiscoverer: Discovers API endpoints in codebase
 * - EndpointAnalyzer: Deep analysis of individual endpoints
 * - VulnVerifier: Verifies findings to reduce false positives
 * - DataFlowTracer: Traces data flow from source to sink
 * - OpenSrcReporter: Generates reports and tracks progress
 */

// New 5-agent architecture exports
export { OpenSrcCoordinatorImpl } from './agents/opensrc-coordinator/index.js';
export { EndpointDiscovererImpl } from './agents/endpoint-discoverer/index.js';
export { OpenSrcReporterImpl } from './agents/opensrc-reporter/index.js';

// Existing agents (unchanged)
export { EndpointAnalyzerImpl } from './agents/endpoint-analyzer/index.js';
export { DataFlowTracerImpl } from './agents/dataflow-tracer/index.js';
export { VulnVerifierImpl } from './agents/vuln-verifier/index.js';

// Legacy export for backward compatibility
export { OpenSrcVulnScannerImpl } from './agents/opensrc-vulnscanner/index.js';

// Types
export * from './types/index.js';
