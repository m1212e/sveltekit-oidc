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
	/**
	 * Set while the signed in user impersonates someone: their own session. Everything else on the
	 * session describes the impersonated user, whose token names this one as its actor (`actors`).
	 */
	impersonator?: OIDCSession;
};

/**
 * The tokens a token exchange issued for the impersonated user, e.g. the result of
 * `OIDC.core.exchangeToken` with the signed in user's token as `actorToken`.
 */
export type ImpersonationTokens = {
	access_token: string;
	id_token?: string;
};
