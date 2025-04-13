import type { OIDCUser, IdTokenResponse, AccessTokenResponse } from './types.ts';

declare global {
	namespace App {
		interface Locals {
			user?: OIDCUser & IdTokenResponse & AccessTokenResponse;
		}
	}
}

// biome-ignore lint/complexity/noUselessEmptyExport:
export {};
