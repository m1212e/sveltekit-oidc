import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { type RequestEvent, isHttpError, isRedirect } from '@sveltejs/kit';
import { type OIDC, type OIDCSession, makeOIDC } from '../src/lib/index.js';
import { APP_ORIGIN, type TestOidcProvider, startTestOidcProvider } from './testOidcProvider.js';

type StoredCookie = { value: string; options: Record<string, unknown> };
type Jar = Map<string, StoredCookie>;

let idp: TestOidcProvider;
let oidc: OIDC;
const loggedIn: OIDCSession[] = [];

beforeAll(async () => {
	idp = await startTestOidcProvider();
	oidc = await makeOIDC({
		issuer: idp.issuer,
		clientId: idp.clientId,
		development: true,
		logLevel: 'silent',
		authenticatedRoutes: ['/app'],
		userLoggedInSuccessfully: (session) => {
			loggedIn.push(session);
		}
	});
});

afterAll(async () => {
	await idp.close();
});

function fakeEvent(path: string, jar: Jar = new Map(), headers?: HeadersInit) {
	const url = new URL(path, APP_ORIGIN);
	const cookies = {
		get: (name: string) => jar.get(name)?.value,
		getAll: () => [...jar].map(([name, { value }]) => ({ name, value })),
		set: (name: string, value: string, options: Record<string, unknown>) => {
			jar.set(name, { value, options });
		},
		delete: (name: string) => {
			jar.delete(name);
		},
		serialize: () => ''
	};
	return {
		url,
		cookies,
		request: new Request(url, { headers }),
		locals: {}
	} as unknown as RequestEvent;
}

type Outcome =
	| { kind: 'resolved'; event: RequestEvent }
	| { kind: 'redirect'; location: string }
	| { kind: 'error'; status: number };

async function run(event: RequestEvent): Promise<Outcome> {
	try {
		await oidc.handle({ event, resolve: async () => new Response('ok') });
		return { kind: 'resolved', event };
	} catch (err) {
		if (isRedirect(err)) return { kind: 'redirect', location: err.location };
		if (isHttpError(err)) return { kind: 'error', status: err.status };
		throw err;
	}
}

function expectRedirect(outcome: Outcome): string {
	if (outcome.kind !== 'redirect') throw new Error(`expected a redirect, got ${outcome.kind}`);
	return outcome.location;
}

async function signIn(accountId: string, path = '/app/page?x=1'): Promise<Jar> {
	const jar: Jar = new Map();
	const authorizationUrl = new URL(expectRedirect(await run(fakeEvent(path, jar))));
	const callbackUrl = await idp.runAuthorizationFlow(authorizationUrl, accountId);
	const location = expectRedirect(await run(fakeEvent(callbackUrl.toString(), jar)));
	expect(location).toBe(path);
	return jar;
}

describe('handle', () => {
	test('lets a visitor without a session through on a public route', async () => {
		const outcome = await run(fakeEvent('/public'));
		expect(outcome.kind).toBe('resolved');
		expect((outcome as { event: RequestEvent }).event.locals.oidc).toBeUndefined();
	});

	test('sends a visitor without a session on a protected route to the provider', async () => {
		const jar: Jar = new Map();
		const location = expectRedirect(await run(fakeEvent('/app/page', jar)));

		const authorizationUrl = new URL(location);
		expect(authorizationUrl.origin).toBe(idp.issuer);
		expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
			`${APP_ORIGIN}/auth/login-callback`
		);
		expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');

		const verifier = jar.get('auth_oidc_code_verifier');
		expect(verifier?.options).toMatchObject({ httpOnly: true, secure: false, maxAge: 300 });
		expect(jar.has('auth_oidc_state')).toBe(true);
	});

	test('signs in, stores the tokens and sends the user back where they came from', async () => {
		const jar = await signIn('alice');

		expect(jar.has('auth_oidc_code_verifier')).toBe(false);
		expect(jar.has('auth_oidc_state')).toBe(false);
		for (const name of [
			'auth_oidc_access_token',
			'auth_oidc_id_token',
			'auth_oidc_refresh_token'
		]) {
			expect(jar.get(name)?.options).toMatchObject({
				path: '/',
				httpOnly: true,
				sameSite: 'lax',
				secure: false,
				maxAge: 60 * 60 * 24 * 30
			});
		}

		const session = loggedIn.at(-1);
		expect(session?.user.sub).toBe('alice');
		expect(session?.user.email).toBe('alice@example.com');
	});

	test('puts the session on locals for a signed in user', async () => {
		const jar = await signIn('bob');
		const outcome = await run(fakeEvent('/app/other', jar));

		expect(outcome.kind).toBe('resolved');
		const session = (outcome as { event: RequestEvent }).event.locals.oidc;
		expect(session?.user.sub).toBe('bob');
		expect(session?.tokens.accessToken).toBe(jar.get('auth_oidc_access_token')?.value);
	});

	test('resumes a session from the refresh token alone and stores the new tokens', async () => {
		const jar = await signIn('carol');
		const oldRefreshToken = jar.get('auth_oidc_refresh_token')?.value;
		jar.delete('auth_oidc_access_token');
		jar.delete('auth_oidc_id_token');

		const outcome = await run(fakeEvent('/app/page', jar));

		expect(outcome.kind).toBe('resolved');
		expect((outcome as { event: RequestEvent }).event.locals.oidc?.user.sub).toBe('carol');
		expect(jar.has('auth_oidc_access_token')).toBe(true);
		expect(jar.get('auth_oidc_refresh_token')?.value).not.toBe(oldRefreshToken);
	});

	test('sends a user with an unusable session to sign in again', async () => {
		const jar: Jar = new Map([
			['auth_oidc_access_token', { value: 'garbage', options: {} }],
			['auth_oidc_refresh_token', { value: 'garbage', options: {} }]
		]);
		const location = expectRedirect(await run(fakeEvent('/app/page', jar)));
		expect(new URL(location).origin).toBe(idp.issuer);
	});

	test('does not carry a refresh token over from an earlier session into a new sign in', async () => {
		const jar: Jar = new Map();
		const authorizationUrl = new URL(expectRedirect(await run(fakeEvent('/app/page', jar))));
		authorizationUrl.searchParams.set('scope', 'openid email');
		const callbackUrl = await idp.runAuthorizationFlow(authorizationUrl, 'grace');
		jar.set('auth_oidc_refresh_token', { value: 'left-over-from-someone-else', options: {} });

		expectRedirect(await run(fakeEvent(callbackUrl.toString(), jar)));
		expect(jar.has('auth_oidc_access_token')).toBe(true);
		expect(jar.has('auth_oidc_refresh_token')).toBe(false);
	});

	test('rejects the callback without the flow cookies', async () => {
		const outcome = await run(fakeEvent('/auth/login-callback?code=x&state=y'));
		expect(outcome).toEqual({ kind: 'error', status: 400 });
	});

	test('rejects the callback with a mismatched state', async () => {
		const jar: Jar = new Map();
		const authorizationUrl = new URL(expectRedirect(await run(fakeEvent('/app/page', jar))));
		const callbackUrl = await idp.runAuthorizationFlow(authorizationUrl, 'mallory');
		callbackUrl.searchParams.set('state', 'tampered');

		const outcome = await run(fakeEvent(callbackUrl.toString(), jar));
		expect(outcome).toEqual({ kind: 'error', status: 400 });
		expect(jar.has('auth_oidc_access_token')).toBe(false);
	});

	test('never returns to another origin after signing in', async () => {
		const event = fakeEvent('/');
		Object.defineProperty(event, 'url', { value: new URL(`${APP_ORIGIN}//evil.example/app`) });

		const location = await oidc.redirectToSignin(event).catch((err) => err.location);
		const authorizationUrl = new URL(location);
		const state = JSON.parse(authorizationUrl.searchParams.get('state') ?? '{}');
		expect(state.visitedUrl).toBe('/');
	});

	test('accepts a valid bearer token and rejects an invalid one', async () => {
		const jar = await signIn('dave');
		const accessToken = jar.get('auth_oidc_access_token')?.value;

		const valid = await run(
			fakeEvent('/api', new Map(), { authorization: `Bearer ${accessToken}` })
		);
		expect(valid.kind).toBe('resolved');
		expect((valid as { event: RequestEvent }).event.locals.oidc?.user.sub).toBe('dave');

		const invalid = await run(fakeEvent('/api', new Map(), { authorization: 'Bearer nope' }));
		expect(invalid).toEqual({ kind: 'error', status: 401 });
	});

	test('clears the session on the logout callback', async () => {
		const jar = await signIn('erin');
		const location = expectRedirect(await run(fakeEvent('/auth/logout-callback', jar)));

		expect(location).toBe('/');
		expect(jar.size).toBe(0);
	});
});

describe('getLogoutUrl', () => {
	test('points back to the logout callback and hints the id token', async () => {
		const jar = await signIn('frank');
		const url = await oidc.getLogoutUrl(fakeEvent('/app', jar));

		expect(url.searchParams.get('post_logout_redirect_uri')).toBe(
			`${APP_ORIGIN}/auth/logout-callback`
		);
		expect(url.searchParams.get('id_token_hint')).toBe(
			jar.get('auth_oidc_id_token')?.value ?? null
		);
	});
});

describe('options', () => {
	test('accepts a function for authenticatedRoutes and a logoutPath without a slash', async () => {
		const custom = await makeOIDC({
			issuer: idp.issuer,
			clientId: idp.clientId,
			development: true,
			logLevel: 'silent',
			authenticatedRoutes: (url) => url.pathname.startsWith('/app') && url.pathname !== '/app',
			logoutPath: 'bye',
			cookiePrefix: 'custom_'
		});
		const handle = (path: string, jar?: Jar) =>
			custom.handle({ event: fakeEvent(path, jar), resolve: async () => new Response('ok') });

		expect(await handle('/app')).toBeInstanceOf(Response);
		await expect(handle('/app/x')).rejects.toMatchObject({ status: 302 });
		expect(custom.cookieNames.state).toBe('custom_state');
		await expect(handle('/auth/logout-callback')).rejects.toMatchObject({
			location: '/bye'
		});
	});
});
