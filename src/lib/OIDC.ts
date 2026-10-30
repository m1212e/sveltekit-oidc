import type { Handle } from '@sveltejs/kit/hooks';
import {
	type Cookies,
	type RequestEvent,
	error,
	isHttpError,
	isRedirect,
	redirect
} from '@sveltejs/kit';
import {
	type OidcCore,
	type OidcCoreOptions,
	type RefreshedTokenSet,
	OidcDelegationError,
	OidcError,
	buildLogger,
	createOidcCore,
	resolveDevelopment,
	returnToFromUrl
} from '@m1212e/oidc';
import { type CookieNames, makeCookieNames } from './cookie.js';
import type { ImpersonationTokens, OIDCSession, SessionTokens } from './types.js';

export type MakeOIDCOptions = OidcCoreOptions & {
	/**
	 * The scope requested on sign in.
	 * @default "openid profile email offline_access"
	 */
	scope?: string;
	/**
	 * Routes that need a session. A visitor without one is sent to the provider to sign in.
	 * Either a list of path prefixes or a function deciding per URL.
	 */
	authenticatedRoutes: string[] | ((url: URL) => boolean);
	/**
	 * Where the provider sends the browser back to after signing in. Served by `handle`, there
	 * does not need to be a route at this path.
	 * @default "/auth/login-callback"
	 */
	loginCallbackRoute?: string;
	/**
	 * Where the provider sends the browser back to after signing out. Served by `handle`, there
	 * does not need to be a route at this path.
	 * @default "/auth/logout-callback"
	 */
	logoutCallbackRoute?: string;
	/**
	 * The path to send the browser to once signed out, e.g. `/logout-successful`.
	 * @default "/"
	 */
	logoutPath?: string;
	/**
	 * The prefix of the cookie names.
	 * @default "auth_oidc_"
	 */
	cookiePrefix?: string;
	/**
	 * How long, in seconds, the token cookies are kept when the provider issued a refresh token.
	 * The tokens themselves still expire on their own schedule and are refreshed as needed, this
	 * only bounds how long a session can be resumed. Without a refresh token the cookies expire
	 * with the access token.
	 * @default 2592000 (30 days)
	 */
	sessionMaxAge?: number;
	/**
	 * Whether to accept a bearer token from the `Authorization` header when there is no session
	 * cookie. Useful for API clients that cannot use cookies.
	 * @default true
	 */
	allowBearerToken?: boolean;
	/**
	 * Called once after a user signed in. Useful for upserting users to a db. `returnTo` is the
	 * same-site path the callback is about to redirect to, so a redirect thrown here can carry it on.
	 */
	userLoggedInSuccessfully?: (
		session: OIDCSession,
		signin: { returnTo: string }
	) => Promise<void> | void;
};

export type OIDC = {
	/**
	 * Protects `authenticatedRoutes`, serves both callback routes and puts the validated session
	 * on `event.locals.oidc`.
	 */
	handle: Handle;
	/**
	 * Builds the provider's logout URL. The provider sends the browser back to
	 * `logoutCallbackRoute`, which clears the session cookies.
	 */
	getLogoutUrl: (event: Pick<RequestEvent, 'url' | 'cookies'>) => Promise<URL>;
	/**
	 * Starts the sign in flow and redirects to the provider. The user is sent back to the
	 * visited URL afterwards.
	 */
	redirectToSignin: (event: RequestEvent) => Promise<never>;
	/**
	 * Starts impersonating the user `tokens` were issued for, from the next request on (and for the
	 * rest of this one, through `event.locals.oidc`). The tokens have to be delegated to the signed
	 * in user: their `act` claim must name them as the current actor. They are stored next to the
	 * session, never in place of it, and checked against it on every request, so the impersonation
	 * ends with the session, when the impersonation token expires (it is never refreshed) or with
	 * `stopImpersonation`.
	 */
	startImpersonation: (event: RequestEvent, tokens: ImpersonationTokens) => Promise<OIDCSession>;
	/**
	 * Ends an impersonation. `event.locals.oidc` is the signed in user's own session again.
	 */
	stopImpersonation: (event: RequestEvent) => void;
	cookieNames: CookieNames;
	/**
	 * The underlying `@m1212e/oidc` instance, for anything this wrapper does not cover.
	 */
	core: OidcCore;
};

const FLOW_COOKIE_MAX_AGE = 60 * 5;
const DEFAULT_SESSION_MAX_AGE = 60 * 60 * 24 * 30;

/**
 * Create an OIDC instance
 */
export async function makeOIDC({
	scope,
	authenticatedRoutes,
	loginCallbackRoute = '/auth/login-callback',
	logoutCallbackRoute = '/auth/logout-callback',
	logoutPath = '/',
	cookiePrefix,
	sessionMaxAge = DEFAULT_SESSION_MAX_AGE,
	allowBearerToken = true,
	userLoggedInSuccessfully,
	...coreOptions
}: MakeOIDCOptions): Promise<OIDC> {
	const core = await createOidcCore(coreOptions);
	const issuer = core.configuration.serverMetadata().issuer;
	const log = buildLogger(coreOptions.logger, coreOptions.logLevel);
	// Browsers drop Secure cookies on plain http://<lan-ip> (only localhost is exempt), which
	// breaks signing in from a phone against a dev server
	const secure = !resolveDevelopment(coreOptions.development);
	const cookieNames = makeCookieNames(cookiePrefix);

	const isAuthenticatedRoute =
		typeof authenticatedRoutes === 'function'
			? authenticatedRoutes
			: (url: URL) => authenticatedRoutes.some((r) => url.pathname.startsWith(r));

	function setCookie(cookies: Cookies, name: string, value: string, maxAge?: number) {
		cookies.set(name, value, { path: '/', httpOnly: true, sameSite: 'lax', secure, maxAge });
	}

	function deleteCookies(cookies: Cookies, names: string[]) {
		for (const name of names) cookies.delete(name, { path: '/' });
	}

	const impersonationCookies = [
		cookieNames.impersonationAccessToken,
		cookieNames.impersonationIdToken
	];

	/**
	 * Writes a token set to the cookies. A refresh does not always return a new refresh token, the
	 * current one then stays valid and is kept. A fresh sign in never inherits one.
	 */
	function storeTokens(
		cookies: Cookies,
		tokens: RefreshedTokenSet,
		{ signin = false } = {}
	): SessionTokens {
		const refreshToken =
			tokens.refresh_token ?? (signin ? undefined : cookies.get(cookieNames.refreshToken));
		const maxAge = refreshToken ? sessionMaxAge : tokens.expiresIn();

		setCookie(cookies, cookieNames.accessToken, tokens.access_token, maxAge);
		// A refresh does not always return a new id token. The old one would then be validated
		// next to the new access token on every request, so it is dropped rather than kept
		if (tokens.id_token) {
			setCookie(cookies, cookieNames.idToken, tokens.id_token, maxAge);
		} else {
			deleteCookies(cookies, [cookieNames.idToken]);
		}
		if (refreshToken) {
			setCookie(cookies, cookieNames.refreshToken, refreshToken, maxAge);
		} else {
			deleteCookies(cookies, [cookieNames.refreshToken]);
		}

		return { accessToken: tokens.access_token, idToken: tokens.id_token, refreshToken };
	}

	/**
	 * Validates the tokens, refreshing them if needed. Refreshed tokens are written back to the
	 * cookies, as providers rotate refresh tokens and the old one stops working once used.
	 */
	async function validateSession(
		event: RequestEvent,
		tokens: SessionTokens
	): Promise<OIDCSession | undefined> {
		try {
			const result = await core.processTokens({
				access_token: tokens.accessToken,
				id_token: tokens.idToken,
				refresh_token: tokens.refreshToken
			});

			if (result.refreshed) {
				tokens = storeTokens(event.cookies, result.refreshedTokens);
			}

			return {
				user: result.user,
				accessTokenClaims: result.accessTokenClaims,
				idTokenClaims: result.idTokenClaims,
				actors: result.actors,
				tokens
			};
		} catch (err) {
			if (err instanceof OidcError && err.refreshedTokens) {
				storeTokens(event.cookies, err.refreshedTokens);
			}
			log.debug('[sveltekit-oidc] session could not be validated:', (err as Error).message);
			return undefined;
		}
	}

	/**
	 * Validates tokens issued to impersonate someone. They are accepted only when they are delegated
	 * to `impersonator`: a token without `act`, or naming anyone else as the current actor, could
	 * otherwise be used to act as its subject without the impersonator's session.
	 */
	async function validateImpersonation(
		tokens: SessionTokens,
		impersonator: OIDCSession
	): Promise<OIDCSession> {
		const actor = impersonator.user.sub;
		const result = await core.processTokens({
			access_token: tokens.accessToken,
			id_token: tokens.idToken,
			delegation: ([current]) =>
				current?.sub === actor && (current.iss === undefined || current.iss === issuer),
			requireActor: true
		});
		if (result.actors[0]?.sub !== actor) {
			throw new OidcDelegationError(
				'access',
				result.actors,
				`an impersonation token has to name the signed in user (${actor}) as its actor`
			);
		}
		return {
			user: result.user,
			accessTokenClaims: result.accessTokenClaims,
			idTokenClaims: result.idTokenClaims,
			actors: result.actors,
			tokens: { accessToken: tokens.accessToken, idToken: tokens.idToken },
			impersonator
		};
	}

	/** Seconds until the earliest of the validated tokens expires. */
	function secondsLeft(session: OIDCSession): number {
		const expiries = [session.accessTokenClaims?.exp, session.idTokenClaims?.exp].filter(
			(exp): exp is number => typeof exp === 'number'
		);
		if (!expiries.length) return 0;
		return Math.max(0, Math.min(...expiries) - Math.floor(Date.now() / 1000));
	}

	/** The impersonation the cookies hold, if it still belongs to `own`. */
	async function resumeImpersonation(
		event: RequestEvent,
		own: OIDCSession
	): Promise<OIDCSession | undefined> {
		const tokens: SessionTokens = {
			accessToken: event.cookies.get(cookieNames.impersonationAccessToken),
			idToken: event.cookies.get(cookieNames.impersonationIdToken)
		};
		if (!tokens.accessToken && !tokens.idToken) return undefined;
		try {
			return await validateImpersonation(tokens, own);
		} catch (err) {
			log.info('[sveltekit-oidc] impersonation ended:', (err as Error).message);
			deleteCookies(event.cookies, impersonationCookies);
			return undefined;
		}
	}

	function hasSessionCookie(cookies: Cookies) {
		return !!(
			cookies.get(cookieNames.accessToken) ||
			cookies.get(cookieNames.idToken) ||
			cookies.get(cookieNames.refreshToken)
		);
	}

	async function startImpersonation(
		event: RequestEvent,
		tokens: ImpersonationTokens
	): Promise<OIDCSession> {
		const own = event.locals.oidc;
		// A bearer request has no cookie session the impersonation could be bound to
		if (!own || !hasSessionCookie(event.cookies)) {
			throw new OidcError('impersonation needs a signed in session');
		}
		if (own.impersonator) {
			throw new OidcError('already impersonating someone, stop that first');
		}
		if (typeof tokens?.access_token !== 'string' || !tokens.access_token) {
			throw new OidcError('impersonation needs the access token the token exchange issued');
		}

		const session = await validateImpersonation(
			{ accessToken: tokens.access_token, idToken: tokens.id_token || undefined },
			own
		);
		const maxAge = secondsLeft(session);
		if (maxAge <= 0) throw new OidcError('the impersonation token carries no future expiry');

		setCookie(event.cookies, cookieNames.impersonationAccessToken, tokens.access_token, maxAge);
		if (tokens.id_token) {
			setCookie(event.cookies, cookieNames.impersonationIdToken, tokens.id_token, maxAge);
		} else {
			deleteCookies(event.cookies, [cookieNames.impersonationIdToken]);
		}
		event.locals.oidc = session;
		return session;
	}

	function stopImpersonation(event: RequestEvent) {
		deleteCookies(event.cookies, impersonationCookies);
		if (event.locals.oidc?.impersonator) {
			event.locals.oidc = event.locals.oidc.impersonator;
		}
	}

	async function redirectToSignin(event: RequestEvent): Promise<never> {
		const { authorizationUrl, codeVerifier, state } = await core.startSignin({
			redirectUri: `${event.url.origin}${loginCallbackRoute}`,
			returnTo: returnToFromUrl(event.url),
			scope
		});

		setCookie(event.cookies, cookieNames.codeVerifier, codeVerifier, FLOW_COOKIE_MAX_AGE);
		setCookie(event.cookies, cookieNames.state, state, FLOW_COOKIE_MAX_AGE);

		redirect(302, authorizationUrl, { external: [authorizationUrl.origin] });
	}

	async function handleLoginCallback(event: RequestEvent): Promise<never> {
		const codeVerifier = event.cookies.get(cookieNames.codeVerifier);
		if (!codeVerifier) error(400, 'No code verifier cookie found.');
		const expectedState = event.cookies.get(cookieNames.state);
		if (!expectedState) error(400, 'No oidc state cookie found.');
		deleteCookies(event.cookies, [
			cookieNames.codeVerifier,
			cookieNames.state,
			...impersonationCookies
		]);

		let returnTo: string;
		try {
			const result = await core.resolveSignin({
				callbackUrl: event.url,
				codeVerifier,
				expectedState
			});
			returnTo = result.returnTo;

			const session = await validateSession(
				event,
				storeTokens(event.cookies, result.tokens, { signin: true })
			);
			if (!session) throw new Error('the tokens returned by the provider could not be validated');
			await userLoggedInSuccessfully?.(session, { returnTo });
		} catch (err) {
			if (isRedirect(err) || isHttpError(err)) throw err;
			log.warn('[sveltekit-oidc] sign in failed:', (err as Error).message);
			deleteCookies(event.cookies, [
				cookieNames.accessToken,
				cookieNames.idToken,
				cookieNames.refreshToken
			]);
			error(400, 'Sign in failed.');
		}

		redirect(302, returnTo);
	}

	function handleLogoutCallback(event: RequestEvent): never {
		deleteCookies(event.cookies, Object.values(cookieNames));
		const target = new URL(logoutPath, `${event.url.origin}/`);
		redirect(302, target.pathname + target.search + target.hash);
	}

	async function getLogoutUrl(event: Pick<RequestEvent, 'url' | 'cookies'>) {
		return core.getLogoutUrl({
			postLogoutRedirectUri: `${event.url.origin}${logoutCallbackRoute}`,
			idTokenHint: event.cookies.get(cookieNames.idToken)
		});
	}

	const handle: Handle = async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(loginCallbackRoute)) {
			await handleLoginCallback(event);
		}
		if (event.url.pathname.startsWith(logoutCallbackRoute)) {
			handleLogoutCallback(event);
		}

		const tokens: SessionTokens = {
			accessToken: event.cookies.get(cookieNames.accessToken),
			idToken: event.cookies.get(cookieNames.idToken),
			refreshToken: event.cookies.get(cookieNames.refreshToken)
		};
		if (tokens.accessToken || tokens.idToken || tokens.refreshToken) {
			const own = await validateSession(event, tokens);
			if (own) {
				event.locals.oidc = (await resumeImpersonation(event, own)) ?? own;
			} else {
				deleteCookies(event.cookies, impersonationCookies);
			}
		} else if (allowBearerToken) {
			const authHeader = event.request.headers.get('authorization');
			if (authHeader?.toLowerCase().startsWith('bearer ')) {
				const accessToken = authHeader.slice(7).trim();
				try {
					const result = await core.processTokens({ access_token: accessToken });
					event.locals.oidc = {
						user: result.user,
						accessTokenClaims: result.accessTokenClaims,
						idTokenClaims: result.idTokenClaims,
						actors: result.actors,
						tokens: { accessToken }
					};
				} catch (err) {
					log.warn('[sveltekit-oidc] bearer token validation failed:', (err as Error).message);
					error(401, 'Invalid bearer token');
				}
			}
		}

		if (!event.locals.oidc && isAuthenticatedRoute(event.url)) {
			await redirectToSignin(event);
		}

		return resolve(event);
	};

	return {
		handle,
		getLogoutUrl,
		redirectToSignin,
		startImpersonation,
		stopImpersonation,
		cookieNames,
		core
	};
}
