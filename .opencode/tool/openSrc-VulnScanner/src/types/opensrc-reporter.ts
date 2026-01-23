/**
 * Types for OpenSrc-Reporter agent
 */

import type { AggregatedFindings } from './opensrc-vulnscanner.js';
import type { AnalysisResult } from './endpoint-analyzer.js';

export interface ReportGenerationOptions {
    outputDir: string;
    codebasePath: string;
}

export interface ReportResult {
    sarifPath: string;
    markdownPath: string;
    statisticsPath: string;
    progressPath: string;
}

export interface ProgressPhase {
    status: 'pending' | 'in_progress' | 'complete' | 'failed';
    startTime?: string;
    endTime?: string;
    result?: any;
}

export interface ProgressData {
    taskId: string;
    codebasePath: string;
    startTime: string;
    currentPhase: string;
    phases: Record<string, ProgressPhase>;
}

export interface AggregationOptions {
    includeLowConfidence?: boolean;
    verifyFindings?: boolean;
}

export interface OpenSrcReporter {
    initProgress(taskId: string, codebasePath: string): Promise<void>;
    updatePhase(taskId: string, phase: string, status: string, result?: any): Promise<void>;
    aggregateAndVerify(results: AnalysisResult[], options?: AggregationOptions): Promise<AggregatedFindings>;
    generateReports(findings: AggregatedFindings, options: ReportGenerationOptions): Promise<ReportResult>;
}
