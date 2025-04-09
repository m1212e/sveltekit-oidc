export function makeCookieNames(prefix?: string) {
	const cookiePrefix = prefix ?? "auth_oidc_";
	const codeVerifierCookieName = `${cookiePrefix}code_verifier`;
	const oidcStateCookieName = `${cookiePrefix}state`;
	const accessTokenCookieName = `${cookiePrefix}access_token`;
	const refreshTokenCookieName = `${cookiePrefix}refresh_token`;
	const idTokenCookieName = `${cookiePrefix}id_token`;
	const expiresInCookieName = `${cookiePrefix}expires_in`;
	const scopeCookieName = `${cookiePrefix}scope`;
	const tokenTypeCookieName = `${cookiePrefix}token_type`;

	return {
		codeVerifierCookieName,
		oidcStateCookieName,
		accessTokenCookieName,
		refreshTokenCookieName,
		idTokenCookieName,
		expiresInCookieName,
		scopeCookieName,
		tokenTypeCookieName,
	};
}
