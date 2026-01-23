/**
 * EndpointDiscoverer - Endpoint discovery agent
 * 
 * Responsibilities:
 * - Discover all remote-accessible endpoints in codebase
 * - Detect authentication mechanisms
 * - Calculate priority scores
 * - Return structured endpoint list
 * 
 * This agent is called by opensrc-coordinator during Phase 1.
 */

import type { Endpoint } from '../../types/index.js';
import { createLogger } from '../../utils/logger.js';
import { discoverEndpoints as discoverEndpointsImpl } from './endpoint-discovery.js';
import { enrichEndpointsWithAuth } from './auth-detection.js';
import { calculateAndSortPriorities, getPriorityStatistics } from './priority-scoring.js';

const logger = createLogger('EndpointDiscoverer');

export interface DiscoveryResult {
    codebasePath: string;
    scanTime: string;
    endpoints: Endpoint[];
    statistics: {
        totalEndpoints: number;
        byMethod: Record<string, number>;
        byAuthStatus: { authenticated: number; public: number };
        byPriority: { HIGH: number; MEDIUM: number; LOW: number };
    };
}

export class EndpointDiscovererImpl {

    async discoverEndpoints(codebasePath: string): Promise<Endpoint[]> {
        logger.info('[DISCOVERY] Scanning codebase', { codebasePath });

        // Step 1: Discover raw endpoints
        let endpoints = await discoverEndpointsImpl(codebasePath);
        logger.info(`[DISCOVERY] Found ${endpoints.length} endpoints`);

        // Step 2: Detect authentication mechanisms
        endpoints = await enrichEndpointsWithAuth(endpoints);
        const authCount = endpoints.filter(e => e.requiresAuth).length;
        logger.info(`[AUTH] Found ${authCount} authenticated, ${endpoints.length - authCount} public endpoints`);

        // Step 3: Calculate priorities and sort
        endpoints = calculateAndSortPriorities(endpoints);
        const priorityStats = getPriorityStatistics(endpoints);
        logger.info('[PRIORITY] Statistics', priorityStats);

        if (endpoints.length > 0) {
            logger.info(`[PRIORITY] Top endpoint: ${endpoints[0].httpMethod} ${endpoints[0].routePattern} (score: ${endpoints[0].priorityScore})`);
        }

        logger.info(`[DISCOVERY] Complete: ${endpoints.length} endpoints cataloged`);

        return endpoints;
    }

    async discoverWithStats(codebasePath: string): Promise<DiscoveryResult> {
        const endpoints = await this.discoverEndpoints(codebasePath);

        // Calculate statistics
        const byMethod: Record<string, number> = {};
        let authenticated = 0;
        let publicCount = 0;
        let high = 0;
        let medium = 0;
        let low = 0;

        for (const endpoint of endpoints) {
            // By method
            const method = endpoint.httpMethod || 'UNKNOWN';
            byMethod[method] = (byMethod[method] || 0) + 1;

            // By auth
            if (endpoint.requiresAuth) {
                authenticated++;
            } else {
                publicCount++;
            }

            // By priority
            const score = endpoint.priorityScore || 50;
            if (score >= 80) high++;
            else if (score >= 50) medium++;
            else low++;
        }

        return {
            codebasePath,
            scanTime: new Date().toISOString(),
            endpoints,
            statistics: {
                totalEndpoints: endpoints.length,
                byMethod,
                byAuthStatus: { authenticated, public: publicCount },
                byPriority: { HIGH: high, MEDIUM: medium, LOW: low },
            },
        };
    }
}
