import { type Handle, type RequestEvent, error, redirect } from '@sveltejs/kit';
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from 'jose';
import {
	type IntrospectionResponse,
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
	skipSubjectCheck,
	tokenIntrospection
} from 'openid-client';
import { makeCookieNames } from './cookie.js';
import { type Logger, type LogLevel, buildLogger } from './logger.js';
import {
	type AccessTokenResponse,
	type IdTokenResponse,
	type OIDCFlowState,
	type RefreshTokenResponse,
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
	authenticatedRoutes,
	allowBearerToken = true,
	logger,
	logLevel
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
	/**
	 * Whether to accept a bearer token from the `Authorization` header when no access token
	 * cookie is present. Useful for API clients that cannot use cookies.
	 * @default true
	 */
	allowBearerToken?: boolean;
	/**
	 * Custom logger instance. Must implement `{ debug, info, warn, error }`.
	 * Compatible with `console`, pino, winston, etc.
	 * When provided, `logLevel` is ignored.
	 */
	logger?: Logger;
	/**
	 * Minimum log level for the built-in logger. Has no effect when `logger` is provided.
	 * @default 'warn'
	 */
	logLevel?: LogLevel;
}) {
	const log = buildLogger(logger, logLevel);

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
	const jwks = jwks_uri ? createRemoteJWKSet(new URL(jwks_uri)) : undefined;

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
	 * Validates a token — any token, access/id/refresh/whatever — using the
	 * same two network-agnostic-first strategy the regular flow relies on: a
	 * local JWT check (works for Zitadel, Keycloak, etc.), falling back to the
	 * introspection endpoint for providers with opaque tokens (e.g. Logto).
	 * Makes no assumption about what kind of token it is. Returns the verified
	 * claims, or `undefined` if neither strategy could confirm it's valid.
	 */
	async function validateToken(
		token: string
	): Promise<JWTPayload | IntrospectionResponse | undefined> {
		if (jwks) {
			try {
				const result = await jwtVerify(token, jwks, {
					issuer: config.serverMetadata().issuer,
					audience: oidcClientId
				});
				return result.payload;
			} catch (error) {
				log.debug('[OIDC] Token JWT verification failed:', (error as Error).message);
			}
		}

		try {
			const result = await tokenIntrospection(config, token);
			if (!result.active) {
				throw new Error('Token is not active');
			}
			return result;
		} catch (error) {
			log.debug('[OIDC] Token introspection failed:', (error as Error).message);
		}

		return undefined;
	}

	/**
	 * Checks whether a token is expired, by decoding it locally — no signature
	 * verification, no network — and comparing its `exp` claim to now. Returns
	 * true if the token isn't a decodable JWT, has no `exp` claim, or has
	 * expired. jose has no ready-made "is this expired" check: `jwtVerify`
	 * enforces `exp` but only as part of a full signature verification, and
	 * `decodeJwt` (used here) is a plain, unverified decode with no exp check
	 * of its own.
	 */
	function isTokenExpired(token: string): boolean {
		try {
			const { exp } = decodeJwt(token);
			if (!exp) return true;
			return exp * 1000 <= Date.now();
		} catch (error) {
			log.debug('[OIDC] Could not decode token to check expiry:', (error as Error).message);
			return true;
		}
	}

	async function validateTokens({
		access_token,
		id_token,
		refresh_token
	}: Pick<
		TokenEndpointResponse,
		'access_token' | 'id_token' | 'refresh_token'
	>): Promise<ValidationResponse> {
		let refreshTokenValue: RefreshTokenResponse = refresh_token;
		if (refresh_token) {
			try {
				refreshTokenValue = decodeJwt(refresh_token);
			} catch (error) {
				log.debug(
					'[OIDC] Refresh token is not a decodable JWT, exposing raw value:',
					(error as Error).message
				);
			}
		}

		const [accessTokenValue, idTokenValue]: [AccessTokenResponse, IdTokenResponse] =
			await Promise.all([
				access_token ? validateToken(access_token) : undefined,
				id_token ? validateToken(id_token) : undefined
			]);

		let finalIdTokenValue = idTokenValue;
		if (access_token && ((!accessTokenValue && access_token) || (!finalIdTokenValue && id_token))) {
			// We have no independently-verified subject to check the userinfo
			// response against here — both tokens failed regular validation, so
			// any `sub` we could decode would come from the same unverified
			// token, adding no real protection over just skipping the check.
			finalIdTokenValue = await fetchUserInfoFromIssuer(access_token, skipSubjectCheck);
		}

		if (
			(accessTokenValue as any)?.sub &&
			finalIdTokenValue?.sub &&
			(accessTokenValue as any)?.sub !== finalIdTokenValue?.sub
		) {
			log.warn('[OIDC] Subject in access token and id token do not match');
			throw new Error('Subject in access token and id token do not match');
		}

		return {
			user: parseOIDCUser({
				...(accessTokenValue || {}),
				...(idTokenValue || {})
			}),
			accessToken: accessTokenValue,
			idToken: idTokenValue,
			refreshToken: refreshTokenValue,
			checkSessionLive: refresh_token ? () => checkSessionLive(refresh_token) : undefined
		};
	}

	/**
	 * Exchanges a refresh token for a new token set via `refreshTokenGrant`.
	 * On providers with refresh token rotation (e.g. Logto), this CONSUMES the
	 * refresh token you pass in — the response's `refresh_token` is the only
	 * one still valid afterwards. Callers MUST persist the new token set
	 * (e.g. via `setTokenCookiesOnRequest`-equivalent cookie writes) somewhere
	 * the browser will actually receive it, or the session becomes permanently
	 * unrefreshable the next time this is called with the now-stale token.
	 * Never call this from a context that can't write the result back to the
	 * client (e.g. mid-connection on an already-open WebSocket) — use
	 * `checkSessionLive`/`isTokenExpired`/`validateToken` instead for
	 * read-only liveness checks that don't consume anything.
	 */
	async function refresh(refresh_token: string) {
		return refreshTokenGrant(config, refresh_token);
	}

	/**
	 * Checks whether a session is still live by introspecting its refresh token
	 * (RFC 7662). Unlike `refresh()`, this is a read-only status query, it never
	 * consumes or rotates the refresh token, and never writes any cookie. Useful
	 * for callers that need to know a session is still valid (e.g. for a
	 * long-lived connection) without triggering a token refresh as a side effect.
	 */
	async function checkSessionLive(refresh_token: string) {
		return tokenIntrospection(config, refresh_token, { token_type_hint: 'refresh_token' });
	}

	async function getLogoutUrl(visitedUrl: URL) {
		return buildEndSessionUrl(config, {
			post_logout_redirect_uri: `${visitedUrl.origin}${logoutCallbackRoute}`
		});
	}

	async function fetchUserInfoFromIssuer(
		access_token: string,
		expectedSubject: string | typeof skipSubjectCheck
	) {
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

		const accessTokenFromCookie = event.cookies.get(accessTokenCookieName);

		// Bearer token auth: used when no cookie is present (e.g. API clients)
		if (allowBearerToken && !accessTokenFromCookie) {
			const authHeader = event.request.headers.get('authorization');
			if (authHeader?.toLowerCase().startsWith('bearer ')) {
				const bearerToken = authHeader.slice(7);
				try {
					event.locals.oidc = await validateTokens({
						access_token: bearerToken,
						id_token: undefined
					});
					return resolve(event);
				} catch (err) {
					log.warn('[OIDC] Bearer token validation failed:', (err as Error).message);
					error(401, 'Invalid bearer token');
				}
			}
		}

		try {
			const accessToken = accessTokenFromCookie;
			const idToken = event.cookies.get(idTokenCookieName);
			const refreshToken = event.cookies.get(refreshTokenCookieName);
			if (!accessToken) {
				error(400, 'No access token found');
			}
			event.locals.oidc = await validateTokens({
				access_token: accessToken,
				id_token: idToken,
				refresh_token: refreshToken
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
				} catch (err) {
					log.warn('[OIDC] Error refreshing token:', (err as Error).message);
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
		getLogoutUrl,
		startSignin,
		resolveSignin,
		handleLoginRedirect,
		handleLogoutRedirect,
		checkSessionLive,
		isTokenExpired,
		validateToken,
		validateTokens,
		refresh
	};
}
