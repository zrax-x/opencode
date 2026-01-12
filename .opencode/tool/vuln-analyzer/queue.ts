/**
 * Task Queue and Orchestration Module
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
 * 
 * Manages the serial execution of vulnerability analysis tasks.
 */

import type { TargetEntry } from "./types"

/**
 * Task status enum
 */
export type TaskStatus = "pending" | "running" | "completed" | "failed" | "skipped"

/**
 * Analysis task interface
 */
export interface AnalysisTask {
  id: string
  target: TargetEntry
  status: TaskStatus
  startTime?: number
  endTime?: number
  error?: string
  findingsCount?: number
  reportPath?: string
}

/**
 * Task queue configuration
 */
export interface QueueConfig {
  maxTasks: number
  continueOnError: boolean
  outputDir: string
}

/**
 * Default queue configuration
 */
export const DEFAULT_QUEUE_CONFIG: QueueConfig = {
  maxTasks: 10,
  continueOnError: true,
  outputDir: "./vuln_reports"
}

/**
 * Generate unique task ID
 */
function generateTaskId(target: TargetEntry, index: number): string {
  const timestamp = Date.now().toString(36)
  const filename = target.filename.replace(/[^a-zA-Z0-9]/g, "_")
  return `task_${index}_${filename}_${timestamp}`
}

/**
 * Create analysis tasks from target list
 * 
 * Property 5: Task Count Correctness
 * For any Target List with M entries and configured limit N,
 * exactly min(N, M) analysis tasks SHALL be created.
 * 
 * Requirement 3.1
 */
export function createTasks(
  targets: TargetEntry[],
  config: QueueConfig = DEFAULT_QUEUE_CONFIG
): AnalysisTask[] {
  // Limit to maxTasks (Requirement 3.1)
  const limitedTargets = targets.slice(0, config.maxTasks)

  return limitedTargets.map((target, index) => ({
    id: generateTaskId(target, index),
    target,
    status: "pending" as TaskStatus
  }))
}

/**
 * Verify task order matches priority order
 * 
 * Property 6: Task Order Preservation
 * For any sequence of analysis task invocations, the order SHALL match
 * the descending priority score order of the Target List.
 * 
 * Requirement 3.2
 */
export function verifyTaskOrder(tasks: AnalysisTask[]): boolean {
  for (let i = 1; i < tasks.length; i++) {
    if (tasks[i].target.priority_score > tasks[i - 1].target.priority_score) {
      return false
    }
  }
  return true
}

/**
 * Task queue class for managing serial execution
 */
export class TaskQueue {
  private tasks: AnalysisTask[]
  private config: QueueConfig
  private currentIndex: number = 0

  constructor(targets: TargetEntry[], config: Partial<QueueConfig> = {}) {
    this.config = { ...DEFAULT_QUEUE_CONFIG, ...config }
    this.tasks = createTasks(targets, this.config)
  }

  /**
   * Get total number of tasks
   */
  getTotalTasks(): number {
    return this.tasks.length
  }

  /**
   * Get current task index
   */
  getCurrentIndex(): number {
    return this.currentIndex
  }

  /**
   * Check if there are more tasks to process
   */
  hasNext(): boolean {
    return this.currentIndex < this.tasks.length
  }

  /**
   * Get the next task to process
   * Requirement 3.2: Tasks are processed in priority order
   */
  getNext(): AnalysisTask | null {
    if (!this.hasNext()) {
      return null
    }
    return this.tasks[this.currentIndex]
  }

  /**
   * Mark current task as started
   */
  startCurrent(): void {
    if (this.currentIndex < this.tasks.length) {
      this.tasks[this.currentIndex].status = "running"
      this.tasks[this.currentIndex].startTime = Date.now()
    }
  }

  /**
   * Mark current task as completed and advance
   * Requirement 3.3: Proceed to next binary after completion
   */
  completeCurrent(findingsCount: number, reportPath: string): void {
    if (this.currentIndex < this.tasks.length) {
      const task = this.tasks[this.currentIndex]
      task.status = "completed"
      task.endTime = Date.now()
      task.findingsCount = findingsCount
      task.reportPath = reportPath
      this.currentIndex++
    }
  }

  /**
   * Mark current task as failed and optionally continue
   * Requirement 3.4: Log error and continue with next binary
   */
  failCurrent(error: string): boolean {
    if (this.currentIndex < this.tasks.length) {
      const task = this.tasks[this.currentIndex]
      task.status = "failed"
      task.endTime = Date.now()
      task.error = error
      this.currentIndex++
    }

    // Return whether to continue (Requirement 3.4)
    return this.config.continueOnError && this.hasNext()
  }

  /**
   * Skip current task
   */
  skipCurrent(reason: string): void {
    if (this.currentIndex < this.tasks.length) {
      const task = this.tasks[this.currentIndex]
      task.status = "skipped"
      task.error = reason
      this.currentIndex++
    }
  }

  /**
   * Get all tasks
   */
  getAllTasks(): AnalysisTask[] {
    return [...this.tasks]
  }

  /**
   * Get completed tasks
   */
  getCompletedTasks(): AnalysisTask[] {
    return this.tasks.filter(t => t.status === "completed")
  }

  /**
   * Get failed tasks
   */
  getFailedTasks(): AnalysisTask[] {
    return this.tasks.filter(t => t.status === "failed")
  }

  /**
   * Get task statistics
   */
  getStatistics(): {
    total: number
    completed: number
    failed: number
    skipped: number
    pending: number
    totalFindings: number
  } {
    const completed = this.tasks.filter(t => t.status === "completed")
    const failed = this.tasks.filter(t => t.status === "failed")
    const skipped = this.tasks.filter(t => t.status === "skipped")
    const pending = this.tasks.filter(t => t.status === "pending")

    return {
      total: this.tasks.length,
      completed: completed.length,
      failed: failed.length,
      skipped: skipped.length,
      pending: pending.length,
      totalFindings: completed.reduce((sum, t) => sum + (t.findingsCount || 0), 0)
    }
  }

  /**
   * Check if all tasks are done
   * Requirement 3.5: Proceed to report aggregation when all complete
   */
  isComplete(): boolean {
    return !this.hasNext()
  }

  /**
   * Get report paths from completed tasks
   */
  getReportPaths(): string[] {
    return this.getCompletedTasks()
      .map(t => t.reportPath)
      .filter((p): p is string => p !== undefined)
  }
}

/**
 * Create a task prompt for VulnFinder-fast agent
 */
export function createTaskPrompt(task: AnalysisTask, outputDir: string): string {
  const target = task.target
  return `Analyze binary: ${target.path}
Binary type: ${target.binary_type}
File size: ${formatFileSize(target.size_bytes)}
Priority score: ${target.priority_score}

Focus on: command injection, buffer overflow, format string, heap vulnerabilities

Output JSON report to: ${outputDir}/vuln_report_${target.filename}_${Date.now()}.json`
}

/**
 * Format file size for display
 */
function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)}KB`
  }
  return `${bytes}B`
}
