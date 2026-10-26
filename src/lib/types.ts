import type { ValidationResult } from '@m1212e/oidc';

export type SessionTokens = {
	accessToken?: string;
	idToken?: string;
	refreshToken?: string;
};

/**
 * The validated session put on `event.locals.oidc`.
 */
export type OIDCSession = ValidationResult & {
	/**
	 * The raw token strings the session was validated from. After a refresh these are the new
	 * tokens, which have already been written back to the cookies.
	 */
	tokens: SessionTokens;
};
