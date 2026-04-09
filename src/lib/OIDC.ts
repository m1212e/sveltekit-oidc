import { type Handle, type RequestEvent, error, redirect } from '@sveltejs/kit';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import {
	type TokenEndpointResponse,
	type TokenEndpointResponseHelpers,
	allowInsecureRequests,
	authorizationCodeGrant,
	buildAuthorizationUrl,
	buildEndSessionUrl,
	calculatePKCECodeChallenge,
	discovery,
	fetchUserInfo,
	randomPKCECodeVerifier,
	randomState,
	refreshTokenGrant,
	tokenIntrospection
} from 'openid-client';
import { makeCookieNames } from './cookie.js';
import {
	type AccessTokenResponse,
	type IdTokenResponse,
	type OIDCFlowState,
	type ValidationResponse,
	parseOIDCFlowState,
	parseOIDCUser
} from './types.js';

// source: https://github.com/panva/jose/blob/2b42c5872b92a2c5662b26facd910b6d8e95f008/src/lib/jwt_claims_set.ts#L19-L31
const checkAudiencePresence = ({
	audOption: audOptionParam,
	audPayload
}: {
	audPayload: string | string[] | undefined;
	audOption: string[] | string;
}) => {
	const audOption = Array.isArray(audOptionParam) ? audOptionParam : [audOptionParam];
	if (typeof audPayload === 'string') {
		return audOption.includes(audPayload);
	}

	if (Array.isArray(audPayload)) {
		// Each principal intended to process the JWT MUST
		// identify itself with a value in the audience claim
		return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
	}

	return false;
};

/**
 * Create an OIDC instance
 */
export async function makeOIDC({
	development = false,
	oidcAuthority,
	oidcClientId,
	oidcClientSecret,
	oidcScope,
	logoutPath = '/',
	cookiePrefix,
	userLoggedInSuccessfully,
	loginCallbackRoute = '/auth/login-callback',
	logoutCallbackRoute = '/auth/logout-callback',
	authenticatedRoutes
}: {
	/**
	 * If the server is running in development mode.
	 * @default false
	 */
	development?: boolean;
	/**
	 * The URL of the OpenID Connect server
	 */
	oidcAuthority: string;
	/**
	 * The client ID of the OpenID client
	 */
	oidcClientId: string;
	/**
	 * The client secret of the OpenID client
	 */
	oidcClientSecret?: string;
	/**
	 * The scope of the requested token
	 */
	oidcScope?: string;
	/**
	 * The path to redirect to after logging out e.g. /logout-successful
	 * Defaults to `/`
	 */
	logoutPath?: string;
	/**
	 * The prefix to use for the cookie names. Defaults to `auth_oidc_`
	 */
	cookiePrefix?: string;
	/**
	 * Callback for when a user logged in successfully. Useful for upserting users to a db
	 */
	userLoggedInSuccessfully?: (oidc: ValidationResponse) => Promise<void> | void;
	/**
	 * The route used for login flow.
	 * Defaults to `/auth/login-callback`
	 * There does not actually have a route +page.svelte file there, the handlers takes
	 * care of all the routing
	 */
	loginCallbackRoute?: string;
	/**
	 * The route used for logout flow.
	 * Defaults to `/auth/logout-callback`
	 * There does not actually have a route +page.svelte file there, the handlers takes
	 * care of all the routing
	 */
	logoutCallbackRoute?: string;
	/**
	 * Routes that are protected and should trigger a login if the user is not authenticated
	 */
	authenticatedRoutes: string[];
}) {
	const execute = [];
	if (development) {
		execute.push(allowInsecureRequests);
	}
	const config = await discovery(
		new URL(oidcAuthority),
		oidcClientId,
		{
			client_secret: oidcClientSecret,
			token_endpoint_auth_method: oidcClientSecret ? undefined : 'none'
		},
		undefined,
		{
			execute
		}
	);

	const jwks_uri = config.serverMetadata().jwks_uri;
	const jwks = jwks_uri ? await createRemoteJWKSet(new URL(jwks_uri)) : undefined;

	const {
		accessTokenCookieName,
		codeVerifierCookieName,
		expiresInCookieName,
		idTokenCookieName,
		oidcStateCookieName,
		refreshTokenCookieName,
		scopeCookieName,
		tokenTypeCookieName
	} = makeCookieNames(cookiePrefix);

	async function startSignin(visitedUrl: URL) {
		const code_verifier = randomPKCECodeVerifier();
		const code_challenge = await calculatePKCECodeChallenge(code_verifier);
		const state: OIDCFlowState = {
			visitedUrl: visitedUrl.toString(),
			random: randomState()
		};
		const serialized_state = JSON.stringify(state);

		const parameters: Record<string, string> = {
			redirect_uri: `${visitedUrl.origin}${loginCallbackRoute}`,
			scope: oidcScope ?? 'openid profile email',
			code_challenge,
			code_challenge_method: 'S256',
			state: serialized_state
		};

		const redirect_uri = buildAuthorizationUrl(config, parameters);

		return {
			code_verifier,
			redirect_uri,
			state: serialized_state
		};
	}

	async function resolveSignin(visitedUrl: URL, verifier: string, state: string) {
		const parsedState = parseOIDCFlowState(JSON.parse(state));
		const tokens = await authorizationCodeGrant(config, visitedUrl, {
			pkceCodeVerifier: verifier,
			expectedState: JSON.stringify(parsedState)
		});
		(parsedState as any).random = undefined;
		const strippedState: Omit<OIDCFlowState, 'random'> = { ...parsedState };

		return { tokens, state: strippedState };
	}

	/**
	 * Try to extract claims from the access token via local JWT verification.
	 * Returns the payload if the token is a valid JWT, or an empty object
	 * if the token is opaque (e.g. Logto without a resource indicator).
	 */
	async function tryVerifyAccessTokenLocally(
		access_token: string
	): Promise<Record<string, unknown>> {
		if (!jwks) return {};
		try {
			// Don't enforce audience here — some providers (e.g. Logto) use a
			// resource indicator as the audience for access tokens, not the client ID.
			const result = await jwtVerify(access_token, jwks, {
				issuer: config.serverMetadata().issuer
			});
			return result.payload;
		} catch {
			return {};
		}
	}

	async function validateTokens({
		access_token,
		id_token
	}: Pick<TokenEndpointResponse, 'access_token' | 'id_token'>): Promise<ValidationResponse> {
		let accessTokenValue: AccessTokenResponse = undefined;
		let idTokenValue: IdTokenResponse = undefined;

		// ── Strategy 1: verify both tokens as JWTs (works for Zitadel, Keycloak, etc.) ──
		try {
			if (!jwks) throw new Error('No jwks available');

			const [at, idt] = await Promise.all([
				jwtVerify(access_token, jwks, {
					issuer: config.serverMetadata().issuer,
					audience: oidcClientId
				}),
				id_token
					? jwtVerify(id_token, jwks, {
							issuer: config.serverMetadata().issuer,
							audience: oidcClientId
						})
					: Promise.resolve(undefined)
			]);

			accessTokenValue = at.payload;
			idTokenValue = idt?.payload;
		} catch (strategy1Error: any) {
			console.debug(
				'[OIDC] Strategy 1 (full local JWT verification) failed:',
				strategy1Error.message
			);

			// ── Strategy 2: verify only the id_token + merge access token claims ──
			// Works for providers with opaque access tokens (e.g. Logto)
			if (jwks && id_token) {
				try {
					const idTokenResult = await jwtVerify(id_token, jwks, {
						issuer: config.serverMetadata().issuer,
						audience: oidcClientId
					});

					const accessTokenClaims = await tryVerifyAccessTokenLocally(access_token);

					const merged = {
						...idTokenResult.payload,
						...accessTokenClaims,
						// Preserve id_token's identity claims over access token's
						sub: idTokenResult.payload.sub,
						aud: idTokenResult.payload.aud,
						iss: idTokenResult.payload.iss
					};

					const user = parseOIDCUser(merged);
					if (user.email) {
						return { user, accessToken: merged, idToken: idTokenResult.payload };
					}

					console.debug(
						'[OIDC] Strategy 2 succeeded for id_token but missing profile fields, falling back to userinfo'
					);

					// id_token verified but incomplete — enrich with userinfo
					const userInfo = await fetchUserInfoFromIssuer(access_token, idTokenResult.payload.sub!);
					const enriched = { ...userInfo, ...merged };
					return {
						user: parseOIDCUser(enriched),
						accessToken: enriched,
						idToken: idTokenResult.payload
					};
				} catch (strategy2Error: any) {
					console.debug(
						'[OIDC] Strategy 2 (id_token verification + userinfo) failed:',
						strategy2Error.message
					);
				}
			}

			// ── Strategy 3: token introspection (original fallback) ──
			// Works for providers that support the introspection endpoint
			try {
				const atTokenIntrospection = await tokenIntrospection(config, access_token);
				const [at, idt] = await Promise.all([
					atTokenIntrospection,
					(async () => {
						try {
							if (!id_token) throw new Error('No id_token available');
							return tokenIntrospection(config, id_token);
						} catch (err) {
							const accessT = await atTokenIntrospection;
							if (!accessT?.sub) throw new Error('No access token available', { cause: err });
							return fetchUserInfoFromIssuer(access_token, accessT.sub);
						}
					})()
				]);

				if (at && !at.active) {
					throw new Error('Access token is not active');
				}

				if (idt && !idt.active) {
					throw new Error('Id token is not active');
				}

				accessTokenValue = at;
				idTokenValue = idt;
			} catch (strategy3Error: any) {
				console.debug('[OIDC] Strategy 3 (token introspection) failed:', strategy3Error.message);

				// ── Strategy 4: userinfo endpoint only (last resort) ──
				try {
					const userInfo = await fetchUserInfoFromIssuer(access_token, 'unknown');
					const accessTokenClaims = await tryVerifyAccessTokenLocally(access_token);
					const merged = { ...userInfo, ...accessTokenClaims };
					const user = parseOIDCUser(merged);
					if (!user.sub) {
						throw new Error('Could not determine user identity from any available method');
					}
					return { user, accessToken: merged, idToken: merged };
				} catch (strategy4Error: any) {
					throw new Error(
						`All token validation strategies failed. ` +
							`Strategy 1 (JWT): ${strategy1Error.message}; ` +
							`Strategy 3 (introspection): ${strategy3Error.message}; ` +
							`Strategy 4 (userinfo): ${strategy4Error.message}`,
						{ cause: strategy4Error }
					);
				}
			}
		}

		if (accessTokenValue?.sub && idTokenValue?.sub && accessTokenValue?.sub !== idTokenValue?.sub) {
			throw new Error('Subject in access token and id token do not match');
		}

		return {
			user: parseOIDCUser({
				...(accessTokenValue || {}),
				...(idTokenValue || {})
			}),
			accessToken: accessTokenValue,
			idToken: idTokenValue
		};
	}

	async function refresh(refresh_token: string) {
		return refreshTokenGrant(config, refresh_token);
	}

	async function getLogoutUrl(visitedUrl: URL) {
		return buildEndSessionUrl(config, {
			post_logout_redirect_uri: `${visitedUrl.origin}${logoutCallbackRoute}`
		});
	}

	async function fetchUserInfoFromIssuer(access_token: string, expectedSubject: string) {
		return fetchUserInfo(config, access_token, expectedSubject);
	}

	async function handleLoginRedirect(req: RequestEvent) {
		const verifier = req.cookies.get(codeVerifierCookieName);
		if (!verifier) error(400, 'No code verifier cookie found.');
		const oidcState = req.cookies.get(oidcStateCookieName);
		if (!oidcState) error(400, 'No oidc state cookie found.');

		const { state, tokens } = await resolveSignin(req.url, verifier, oidcState);

		setTokenCookiesOnRequest(req, tokens);

		req.cookies.delete(codeVerifierCookieName, { path: '/' });
		req.cookies.delete(oidcStateCookieName, { path: '/' });

		const oidc = await validateTokens(tokens);
		await userLoggedInSuccessfully?.(oidc);

		redirect(302, state.visitedUrl);
	}

	function setTokenCookiesOnRequest(
		req: RequestEvent,
		tokens: TokenEndpointResponse & TokenEndpointResponseHelpers
	) {
		const cookieOptions: Parameters<typeof req.cookies.set>[2] = {
			path: '/',
			httpOnly: true,
			sameSite: 'lax',
			// sameSite: 'strict',
			secure: true,
			maxAge: tokens.expires_in ? tokens.expires_in : undefined
		};

		req.cookies.set(accessTokenCookieName, tokens.access_token, cookieOptions);
		if (tokens.refresh_token) {
			req.cookies.set(refreshTokenCookieName, tokens.refresh_token, cookieOptions);
		}
		if (tokens.id_token) {
			req.cookies.set(idTokenCookieName, tokens.id_token, cookieOptions);
		}
		const expiresIn = tokens.expiresIn();
		if (expiresIn) {
			req.cookies.set(expiresInCookieName, expiresIn.toString(), cookieOptions);
		}
		if (tokens.scope) {
			req.cookies.set(scopeCookieName, tokens.scope, cookieOptions);
		}
		if (tokens.token_type) {
			req.cookies.set(tokenTypeCookieName, tokens.token_type, cookieOptions);
		}
	}

	async function handleLogoutRedirect(req: RequestEvent) {
		req.cookies.delete(codeVerifierCookieName, { path: '/' });
		req.cookies.delete(oidcStateCookieName, { path: '/' });
		req.cookies.delete(accessTokenCookieName, { path: '/' });
		req.cookies.delete(refreshTokenCookieName, { path: '/' });
		req.cookies.delete(idTokenCookieName, { path: '/' });
		req.cookies.delete(expiresInCookieName, { path: '/' });
		req.cookies.delete(scopeCookieName, { path: '/' });
		req.cookies.delete(tokenTypeCookieName, { path: '/' });

		redirect(302, `${req.url.origin}/${logoutPath}`);
	}

	const handle: Handle = async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(loginCallbackRoute)) {
			await handleLoginRedirect(event);
		}

		if (event.url.pathname.startsWith(logoutCallbackRoute)) {
			await handleLogoutRedirect(event);
		}

		try {
			const accessToken = event.cookies.get(accessTokenCookieName);
			const idToken = event.cookies.get(idTokenCookieName);
			if (!accessToken) {
				error(400, 'No access token found');
			}
			event.locals.oidc = await validateTokens({
				access_token: accessToken,
				id_token: idToken
			});

			return resolve(event);
		} catch (error) {
			const refreshToken = event.cookies.get(refreshTokenCookieName);
			if (refreshToken) {
				try {
					const newTokenSet = await refresh(refreshToken);
					setTokenCookiesOnRequest(event, newTokenSet);
					event.locals.oidc = await validateTokens(newTokenSet);
					return resolve(event);
				} catch (error) {
					// console.warn('Error refreshing token', error);
				}
			}

			// if neither validation nor refresh worked, start login flow
			// but only if a route is protected
			if (!authenticatedRoutes.some((r) => event.url.pathname.startsWith(r))) {
				return resolve(event);
			}

			const { state, code_verifier, redirect_uri } = await startSignin(event.url);

			event.cookies.set(codeVerifierCookieName, code_verifier, {
				sameSite: 'lax',
				maxAge: 60 * 5,
				path: '/',
				secure: true,
				httpOnly: true
			});

			event.cookies.set(oidcStateCookieName, state, {
				sameSite: 'lax',
				maxAge: 60 * 5,
				path: '/',
				secure: true,
				httpOnly: true
			});

			redirect(302, redirect_uri.toString());
		}
	};

	return {
		handle,
		fetchUserInfoFromIssuer,
		getLogoutUrl
	};
}
