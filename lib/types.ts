import { z } from "zod";

export const OIDCUserSchema = z.object({
	sub: z.string(),
	email: z.string(),
	preferred_username: z.string(),
	family_name: z.string(),
	given_name: z.string(),

	locale: z.string().optional(),
	phone: z.string().optional(),
});
export type OIDCUser = z.infer<typeof OIDCUserSchema>;
export function isValidOIDCUser(user: unknown): user is OIDCUser {
	return OIDCUserSchema.safeParse(user).success;
}

export const OIDCFlowStateSchema = z.object({
	visitedUrl: z.string(),
	random: z.string(),
});
export type OIDCFlowState = z.infer<typeof OIDCFlowStateSchema>;
export function isValidOIDCFlowState(state: unknown): state is OIDCFlowState {
	return OIDCFlowStateSchema.safeParse(state).success;
}
