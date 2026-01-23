/**
 * Example usage of OpenSrc-VulnScanner
 * 
 * This demonstrates how to scan a codebase for vulnerabilities
 */

import { OpenSrcVulnScannerImpl } from './src/index.js';

async function main() {
  // Create scanner instance
  const scanner = new OpenSrcVulnScannerImpl();

  console.log('Starting vulnerability scan...\n');

  try {
    // Run the scan
    const result = await scanner.scanCodebase({
      codebasePath: process.argv[2] || './test-codebase',
      outputDir: './reports',
      concurrency: 5,
      topN: 50,
      includeLowConfidence: false,
    });

    // Display results
    console.log('\n=== Scan Results ===\n');
    console.log(`Total Endpoints: ${result.summary.totalEndpoints}`);
    console.log(`Analyzed Endpoints: ${result.summary.analyzedEndpoints}`);
    console.log(`Total Findings: ${result.summary.totalFindings}`);
    console.log(`Execution Time: ${result.executionTime}ms\n`);

    console.log('By Severity:');
    console.log(`  CRITICAL: ${result.summary.bySeverity.CRITICAL}`);
    console.log(`  HIGH: ${result.summary.bySeverity.HIGH}`);
    console.log(`  MEDIUM: ${result.summary.bySeverity.MEDIUM}`);
    console.log(`  LOW: ${result.summary.bySeverity.LOW}\n`);

    console.log('By Type:');
    console.log(`  RCE: ${result.summary.byType.RCE}`);
    console.log(`  Command Injection: ${result.summary.byType.COMMAND_INJECTION}`);
    console.log(`  Auth Bypass: ${result.summary.byType.AUTH_BYPASS}`);
    console.log(`  Arbitrary File Read: ${result.summary.byType.ARBITRARY_FILE_READ}`);
    console.log(`  Path Traversal: ${result.summary.byType.PATH_TRAVERSAL}\n`);

    console.log('By Confidence:');
    console.log(`  HIGH: ${result.summary.byConfidence.HIGH_CONFIDENCE}`);
    console.log(`  MEDIUM: ${result.summary.byConfidence.MEDIUM_CONFIDENCE}`);
    console.log(`  LOW: ${result.summary.byConfidence.LOW_CONFIDENCE}\n`);

    console.log(`SARIF Report: ${result.sarifReportPath}`);

    if (result.errors.length > 0) {
      console.log(`\nErrors encountered: ${result.errors.length}`);
      result.errors.slice(0, 5).forEach((error, i) => {
        console.log(`  ${i + 1}. ${error}`);
      });
    }
  } catch (error) {
    console.error('Scan failed:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
