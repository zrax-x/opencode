/**
 * SARIF Report Generator Module
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
 * 
 * Generates SARIF 2.1.0 format reports for vulnerability findings.
 */

import { writeFileSync } from "fs"
import type {
  AggregatedFinding,
  AggregatedReport,
  SARIFReport,
  SARIFRun,
  SARIFTool,
  SARIFToolDriver,
  SARIFResult,
  SARIFReportingDescriptor,
  SARIFLocation,
  SARIFCodeFlow,
  SARIFInvocation,
  SARIFLevel,
  VulnerabilityType
} from "./types"
import { CWE_MAPPINGS } from "./cwe"

// Tool information
const TOOL_NAME = "Firmware Vulnerability Analyzer"
const TOOL_VERSION = "1.0.0"
const TOOL_INFO_URI = "https://github.com/opencode/firmware-vuln-analyzer"

// SARIF schema
const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

/**
 * Map severity to SARIF level
 */
function severityToLevel(severity: string): SARIFLevel {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error"
    case "MEDIUM":
      return "warning"
    case "LOW":
      return "note"
    case "INFO":
    default:
      return "none"
  }
}

/**
 * Generate rule ID from vulnerability type and CWE
 */
function generateRuleId(vulnType: VulnerabilityType, cweId: string): string {
  return `${vulnType.toUpperCase()}/${cweId}`
}

/**
 * Create SARIF reporting descriptor (rule) for a vulnerability type
 */
function createRule(vulnType: VulnerabilityType): SARIFReportingDescriptor {
  const cweMapping = CWE_MAPPINGS[vulnType]
  
  return {
    id: generateRuleId(vulnType, cweMapping.id),
    name: cweMapping.name,
    shortDescription: {
      text: cweMapping.name
    },
    fullDescription: {
      text: cweMapping.description
    },
    helpUri: `https://cwe.mitre.org/data/definitions/${cweMapping.id.replace("CWE-", "")}.html`,
    defaultConfiguration: {
      level: "error"
    }
  }
}

/**
 * Create all rules for the tool driver
 */
function createRules(): SARIFReportingDescriptor[] {
  const vulnTypes: VulnerabilityType[] = [
    "command_injection",
    "buffer_overflow",
    "format_string",
    "heap_vulnerability"
  ]
  
  return vulnTypes.map(createRule)
}

/**
 * Create SARIF tool driver
 * Requirement 10.2
 */
function createToolDriver(): SARIFToolDriver {
  return {
    name: TOOL_NAME,
    version: TOOL_VERSION,
    informationUri: TOOL_INFO_URI,
    rules: createRules()
  }
}

/**
 * Create SARIF tool
 */
function createTool(): SARIFTool {
  return {
    driver: createToolDriver()
  }
}

/**
 * Create SARIF location from finding
 */
function createLocation(finding: AggregatedFinding): SARIFLocation {
  return {
    physicalLocation: {
      artifactLocation: {
        uri: finding.binary_path
      },
      region: {
        snippet: {
          text: finding.pseudocode
        }
      }
    },
    message: {
      text: `Function: ${finding.function_name} at ${finding.function_address}`
    }
  }
}

/**
 * Create SARIF code flow from call chain
 * Requirement 10.4
 */
function createCodeFlow(finding: AggregatedFinding): SARIFCodeFlow | undefined {
  if (!finding.call_chain || finding.call_chain.length === 0) {
    return undefined
  }

  return {
    threadFlows: [{
      locations: finding.call_chain.map((func, index) => ({
        location: {
          physicalLocation: {
            artifactLocation: {
              uri: finding.binary_path
            }
          },
          message: {
            text: func
          }
        },
        nestingLevel: index
      }))
    }],
    message: {
      text: `Call chain leading to ${finding.sink_function}`
    }
  }
}

/**
 * Create related locations for affected binaries
 */
function createRelatedLocations(finding: AggregatedFinding): SARIFLocation[] {
  return finding.affected_binaries.map(binary => ({
    physicalLocation: {
      artifactLocation: {
        uri: binary
      }
    },
    message: {
      text: `Also affects: ${binary}`
    }
  }))
}

/**
 * Create SARIF result from finding
 * Requirement 10.3
 */
function createResult(finding: AggregatedFinding): SARIFResult {
  const cweMapping = CWE_MAPPINGS[finding.vulnerability_type]
  const ruleId = generateRuleId(finding.vulnerability_type, cweMapping.id)
  
  const result: SARIFResult = {
    ruleId,
    level: severityToLevel(finding.severity),
    message: {
      text: `${cweMapping.name} vulnerability found in ${finding.function_name} calling ${finding.sink_function}`,
      markdown: `**${cweMapping.name}** vulnerability found in \`${finding.function_name}\` calling \`${finding.sink_function}\`\n\n` +
        `**Severity:** ${finding.severity}\n` +
        `**Confidence:** ${finding.confidence}\n` +
        `**CWE:** ${finding.cwe_id}\n\n` +
        `**Exploitability:** ${finding.exploitability}\n\n` +
        `**Argument Analysis:**\n` +
        `- Index: ${finding.argument_analysis.argument_index}\n` +
        `- Source: ${finding.argument_analysis.source}\n` +
        `- Controllability: ${finding.argument_analysis.controllability}`
    },
    locations: [createLocation(finding)],
    fingerprints: {
      "primaryLocationLineHash": finding.id
    }
  }

  // Add code flow if call chain exists
  const codeFlow = createCodeFlow(finding)
  if (codeFlow) {
    result.codeFlows = [codeFlow]
  }

  // Add related locations for multiple affected binaries
  if (finding.affected_binaries.length > 1) {
    result.relatedLocations = createRelatedLocations(finding)
  }

  return result
}

/**
 * Create SARIF invocation
 */
function createInvocation(
  startTime: string,
  endTime: string,
  successful: boolean
): SARIFInvocation {
  return {
    executionSuccessful: successful,
    startTimeUtc: startTime,
    endTimeUtc: endTime
  }
}

/**
 * Create SARIF run
 */
function createRun(
  findings: AggregatedFinding[],
  startTime: string,
  endTime: string
): SARIFRun {
  return {
    tool: createTool(),
    results: findings.map(createResult),
    invocations: [createInvocation(startTime, endTime, true)]
  }
}

/**
 * Generate SARIF report from aggregated report
 * 
 * Property 15: SARIF Schema Compliance
 * For any generated SARIF report, the output SHALL be valid JSON
 * conforming to SARIF 2.1.0 schema.
 * 
 * Requirements: 10.1, 10.2, 10.3, 10.4
 */
export function generateSARIFReport(
  aggregatedReport: AggregatedReport,
  startTime?: string,
  endTime?: string
): SARIFReport {
  const start = startTime || aggregatedReport.analysis_timestamp
  const end = endTime || new Date().toISOString()

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [createRun(aggregatedReport.findings, start, end)]
  }
}

/**
 * Serialize SARIF report to JSON string
 */
export function serializeSARIF(report: SARIFReport): string {
  return JSON.stringify(report, null, 2)
}

/**
 * Save SARIF report to file
 * Requirement 10.5
 */
export function saveSARIFReport(report: SARIFReport, outputPath: string): void {
  const jsonContent = serializeSARIF(report)
  writeFileSync(outputPath, jsonContent, "utf-8")
}

/**
 * Parse SARIF report from JSON string
 * Used for round-trip testing
 */
export function parseSARIF(jsonString: string): SARIFReport {
  return JSON.parse(jsonString) as SARIFReport
}

/**
 * Extract findings from SARIF report
 * Used for round-trip testing
 * 
 * Property 16: SARIF Round-Trip Consistency
 */
export function extractFindingsFromSARIF(report: SARIFReport): Array<{
  ruleId: string
  severity: string
  location: string
  cweId: string
}> {
  const findings: Array<{
    ruleId: string
    severity: string
    location: string
    cweId: string
  }> = []

  for (const run of report.runs) {
    for (const result of run.results) {
      const location = result.locations[0]?.physicalLocation?.artifactLocation?.uri || ""
      const cweId = result.ruleId.split("/")[1] || ""
      
      findings.push({
        ruleId: result.ruleId,
        severity: result.level,
        location,
        cweId
      })
    }
  }

  return findings
}
