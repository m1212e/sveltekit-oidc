import type { OIDCSession } from './types.js';

declare global {
	namespace App {
		interface Locals {
			oidc?: OIDCSession;
		}
	}
}

// biome-ignore lint/complexity/noUselessEmptyExport:
export {};
