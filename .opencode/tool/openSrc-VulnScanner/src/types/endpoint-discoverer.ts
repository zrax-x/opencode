/**
 * Types for EndpointDiscoverer agent
 */

import type { Endpoint } from './common.js';

export interface DiscoveryStatistics {
    totalEndpoints: number;
    byMethod: Record<string, number>;
    byAuthStatus: {
        authenticated: number;
        public: number;
    };
    byPriority: {
        HIGH: number;
        MEDIUM: number;
        LOW: number;
    };
}

export interface DiscoveryResult {
    codebasePath: string;
    scanTime: string;
    endpoints: Endpoint[];
    statistics: DiscoveryStatistics;
}

export interface EndpointDiscoverer {
    discoverEndpoints(codebasePath: string): Promise<Endpoint[]>;
    discoverWithStats(codebasePath: string): Promise<DiscoveryResult>;
}
