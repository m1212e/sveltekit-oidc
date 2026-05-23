export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

export type Logger = {
	debug: (...args: unknown[]) => void;
	info: (...args: unknown[]) => void;
	warn: (...args: unknown[]) => void;
	error: (...args: unknown[]) => void;
};

const LEVELS: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

const noop = () => {};

export function buildLogger(logger?: Logger, logLevel?: LogLevel): Logger {
	if (logger) return logger;
	const threshold = LEVELS[logLevel ?? 'warn'];
	return {
		error: threshold >= LEVELS.error ? (...args) => console.error(...args) : noop,
		warn: threshold >= LEVELS.warn ? (...args) => console.warn(...args) : noop,
		info: threshold >= LEVELS.info ? (...args) => console.info(...args) : noop,
		debug: threshold >= LEVELS.debug ? (...args) => console.debug(...args) : noop
	};
}
