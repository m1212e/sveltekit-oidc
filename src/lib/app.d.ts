import type { ValidationResponse } from './types.ts';

declare global {
	namespace App {
		interface Locals {
			oidc?: ValidationResponse;
		}
	}
}

// biome-ignore lint/complexity/noUselessEmptyExport:
export {};
