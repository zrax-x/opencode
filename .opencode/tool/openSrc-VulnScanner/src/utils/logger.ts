/**
 * Logging utility for vulnerability scanner
 */

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  agent: string;
  message: string;
  context?: Record<string, any>;
  errorType?: string;
  stackTrace?: string;
  recovery?: string;
}

export class Logger {
  private agent: string;
  private minLevel: LogLevel;

  constructor(agent: string, minLevel: LogLevel = 'INFO') {
    this.agent = agent;
    this.minLevel = minLevel;
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['DEBUG', 'INFO', 'WARN', 'ERROR'];
    return levels.indexOf(level) >= levels.indexOf(this.minLevel);
  }

  private formatLog(entry: LogEntry): string {
    return JSON.stringify(entry, null, 2);
  }

  private log(level: LogLevel, message: string, context?: Record<string, any>): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      agent: this.agent,
      message,
      context,
    };

    const formatted = this.formatLog(entry);

    switch (level) {
      case 'DEBUG':
      case 'INFO':
        console.log(formatted);
        break;
      case 'WARN':
        console.warn(formatted);
        break;
      case 'ERROR':
        console.error(formatted);
        break;
    }
  }

  debug(message: string, context?: Record<string, any>): void {
    this.log('DEBUG', message, context);
  }

  info(message: string, context?: Record<string, any>): void {
    this.log('INFO', message, context);
  }

  warn(message: string, context?: Record<string, any>): void {
    this.log('WARN', message, context);
  }

  error(
    message: string,
    error?: Error,
    context?: Record<string, any>,
    recovery?: string
  ): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      agent: this.agent,
      message,
      context,
      errorType: error?.name,
      stackTrace: error?.stack,
      recovery,
    };

    console.error(this.formatLog(entry));
  }
}

// Factory function for creating loggers
export function createLogger(agent: string, minLevel?: LogLevel): Logger {
  return new Logger(agent, minLevel);
}
