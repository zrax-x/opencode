# OpenSrc-VulnScanner

Multi-agent vulnerability scanner for open source codebases.

## Architecture (v2.0 - 5 Agents)

```
┌─────────────────────────────────────────────────────────────────┐
│                    opensrc-coordinator                          │
│                    (Pure Orchestrator)                          │
└──────┬────────────────┬─────────────────┬──────────────────┬────┘
       │                │                 │                  │
       ▼                ▼                 ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  endpoint-   │ │  endpoint-   │ │   vuln-      │ │  opensrc-    │
│  discoverer  │ │  analyzer    │ │  verifier    │ │  reporter    │
│              │ │       │      │ │              │ │              │
│ Phase 1:     │ │ Phase 2:     │ │ Phase 3:     │ │ Phase 4:     │
│ Discovery    │ │ Analysis     │ │ Verification │ │ Reporting    │
└──────────────┘ └───────┬──────┘ └──────────────┘ └──────────────┘
                         │
                         ▼
                 ┌──────────────┐
                 │  dataflow-   │
                 │  tracer      │
                 └──────────────┘
```

### Agent Responsibilities

| Agent | Mode | Responsibility |
|-------|------|----------------|
| **opensrc-coordinator** | Primary | Pure orchestration: receives tasks, dispatches to agents, aggregates results |
| **endpoint-discoverer** | Subagent | Discovers API endpoints, detects auth, calculates priority scores |
| **endpoint-analyzer** | Subagent | Deep analysis of individual endpoints for vulnerabilities |
| **vuln-verifier** | Subagent | Independent verification to reduce false positives |
| **dataflow-tracer** | Subagent | Traces data flow from user input to dangerous sinks |
| **opensrc-reporter** | Subagent | Generates SARIF reports, Markdown summaries, tracks progress |

## Features

- **Endpoint Discovery**: Automatically discovers all remote-accessible endpoints (HTTP APIs, gRPC, WebSocket)
- **Multi-Language Support**: Python, Node.js, Java, Go, Rust, C/C++
- **Vulnerability Detection**: RCE, Command Injection, Auth Bypass, Arbitrary File Read, Path Traversal
- **Multi-Agent Architecture**: 5 specialized agents with clear separation of concerns
- **SARIF Reports**: Industry-standard vulnerability reporting format (SARIF 2.1.0)
- **Priority Scoring**: Intelligent prioritization based on risk factors
- **Authentication Detection**: Identifies auth mechanisms and adjusts severity
- **Data Flow Analysis**: Traces user input to dangerous sinks
- **Verification System**: Reduces false positives through independent verification
- **Progress Tracking**: Real-time progress tracking with JSON output

## Supported Languages & Frameworks

- **Python**: Flask, Django, FastAPI, aiohttp, Tornado
- **Node.js**: Express, Koa, Fastify, NestJS
- **Java**: Spring Boot, JAX-RS, Servlet, Netty
- **Go**: net/http, Gin, Echo, Fiber, gRPC
- **Rust**: Actix-web, Rocket, Axum, Warp, Tonic
- **C/C++**: Socket APIs, HTTP libraries (evhtp), **brpc (Baidu RPC)**

## Vulnerability Types

- **Remote Code Execution (RCE)** - CWE-94
- **Command Injection** - CWE-78
- **Authentication Bypass** - CWE-287
- **Arbitrary File Read** - CWE-22
- **Path Traversal** - CWE-22

## Installation

```bash
bun install
```

## Usage

### New: Using the Coordinator (Recommended)

```typescript
import { OpenSrcCoordinatorImpl } from '@opencode/opensrc-vulnscanner';

const coordinator = new OpenSrcCoordinatorImpl();

const result = await coordinator.coordinateAnalysis({
  codebasePath: '/path/to/codebase',
  outputDir: './OpenSrc-VulnScanner-Reports',
  concurrency: 5,           // Parallel analysis tasks
  topN: 50,                 // Analyze top 50 priority endpoints
  includeLowConfidence: false,  // Filter out low confidence findings
});

console.log(`Scanned ${result.summary.totalEndpoints} endpoints`);
console.log(`Found ${result.summary.totalFindings} vulnerabilities`);
console.log(`Report: ${result.sarifReportPath}`);
```

### Legacy: Direct Scanner Usage

```typescript
import { OpenSrcVulnScannerImpl } from '@opencode/opensrc-vulnscanner';

const scanner = new OpenSrcVulnScannerImpl();
const result = await scanner.scanCodebase({
  codebasePath: '/path/to/codebase',
  outputDir: './OpenSrc-VulnScanner-Reports',
});
```

### Using Individual Agents

```typescript
import { 
  EndpointDiscovererImpl,
  EndpointAnalyzerImpl,
  VulnVerifierImpl,
  OpenSrcReporterImpl,
} from '@opencode/opensrc-vulnscanner';

// Discover endpoints
const discoverer = new EndpointDiscovererImpl();
const endpoints = await discoverer.discoverEndpoints('/path/to/codebase');

// Analyze an endpoint
const analyzer = new EndpointAnalyzerImpl();
const result = await analyzer.analyzeEndpoint({ endpoint: endpoints[0] });

// Verify a finding
const verifier = new VulnVerifierImpl();
const verification = await verifier.verifyVulnerability(result.findings[0]);

// Generate reports
const reporter = new OpenSrcReporterImpl();
await reporter.generateReports(aggregatedFindings, { outputDir: './reports', codebasePath: '...' });
```

## Output Files

The scanner generates these files in the output directory:

| File | Description |
|------|-------------|
| `vulnerability_report_*.sarif` | SARIF 2.1.0 format report (machine-readable) |
| `vulnerability_report_*.md` | Markdown summary (human-readable) |
| `statistics.json` | Raw statistics data |
| `progress.json` | Analysis progress log |

## Configuration Options

```typescript
interface ScanOptions {
  codebasePath: string;      // Path to codebase to scan
  outputDir: string;         // Directory for reports
  concurrency?: number;      // Parallel tasks (default: 5)
  topN?: number;            // Limit to top N endpoints
  includeLowConfidence?: boolean;  // Include low confidence findings
  languages?: string[];     // Filter by languages
}
```

## Priority Scoring

Endpoints are scored based on:
- **Name keywords**: admin (+30), auth (+25), exec (+25), upload (+20), etc.
- **Chinese keywords**: 管理 (+30), 认证 (+25), 上传 (+20), 执行 (+25), etc.
- **Authentication**: No auth (+20), With auth (+0)
- **Priority levels**: HIGH (≥80), MEDIUM (50-79), LOW (<50)

## Development

```bash
# Build TypeScript
bun run build

# Run tests
bun test

# Run tests in watch mode
bun test:watch

# Lint code
bun run lint

# Clean build artifacts
bun run clean
```

## License

See LICENSE file in repository root.
