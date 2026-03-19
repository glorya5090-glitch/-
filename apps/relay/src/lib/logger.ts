import { env } from '@/env';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const severity: Record<LogLevel, number> = {
  debug: 10,
  error: 40,
  info: 20,
  warn: 30,
};

const currentSeverity = severity[env.LOG_LEVEL];

const shouldLog = (level: LogLevel): boolean => severity[level] >= currentSeverity;

const formatEntry = (level: LogLevel, message: string, data?: Record<string, unknown>): string => {
  const entry = {
    data,
    level,
    message,
    service: 'agentpay-relay',
    timestamp: new Date().toISOString(),
  };

  return env.RELAY_ENABLE_PRETTY_LOGS
    ? `${entry.timestamp} ${level.toUpperCase()} ${message}`
    : JSON.stringify(entry);
};

const write = (level: LogLevel, message: string, data?: Record<string, unknown>): void => {
  if (!shouldLog(level)) {
    return;
  }

  const line = formatEntry(level, message, data);
  if (level === 'error') {
    console.error(line);
    return;
  }

  if (level === 'warn') {
    console.warn(line);
    return;
  }

  console.log(line);
};

export const log = {
  debug: (message: string, data?: Record<string, unknown>) => write('debug', message, data),
  error: (message: string, data?: Record<string, unknown>) => write('error', message, data),
  info: (message: string, data?: Record<string, unknown>) => write('info', message, data),
  warn: (message: string, data?: Record<string, unknown>) => write('warn', message, data),
};
