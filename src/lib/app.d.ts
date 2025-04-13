import type { OIDCUser } from './types.js';

declare global {
	namespace App {
		interface Locals {
			user?: OIDCUser;
		}
	}
}

// biome-ignore lint/complexity/noUselessEmptyExport:
export {};
