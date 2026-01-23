/**
 * Types for OpenSrc-Coordinator orchestrator agent
 */

import type { ScanOptions, ScanResult, Endpoint } from './common.js';
import type { AnalysisResult } from './endpoint-analyzer.js';
import type { AggregatedFindings } from './opensrc-vulnscanner.js';

export interface CoordinatorPhase {
    name: string;
    status: 'pending' | 'in_progress' | 'complete' | 'failed';
    startTime?: string;
    endTime?: string;
    result?: any;
}

export interface CoordinatorProgress {
    taskId: string;
    codebasePath: string;
    startTime: string;
    currentPhase: string;
    phases: Record<string, CoordinatorPhase>;
}

export interface OpenSrcCoordinator {
    coordinateAnalysis(options: ScanOptions): Promise<ScanResult>;
}

export type { ScanOptions, ScanResult, Endpoint, AnalysisResult, AggregatedFindings };
