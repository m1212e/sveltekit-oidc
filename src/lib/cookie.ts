export type CookieNames = ReturnType<typeof makeCookieNames>;

export function makeCookieNames(prefix = 'auth_oidc_') {
	return {
		codeVerifier: `${prefix}code_verifier`,
		state: `${prefix}state`,
		accessToken: `${prefix}access_token`,
		idToken: `${prefix}id_token`,
		refreshToken: `${prefix}refresh_token`,
		impersonationAccessToken: `${prefix}impersonation_access_token`,
		impersonationIdToken: `${prefix}impersonation_id_token`
	};
}
