import type { applyAuth } from "$api/services/OIDC";
import type { OIDCUser } from "./types";

declare global {
	namespace App {
		interface Locals {
			user?: OIDCUser;
		}
	}
}

// biome-ignore lint/complexity/noUselessEmptyExport:
export {};
