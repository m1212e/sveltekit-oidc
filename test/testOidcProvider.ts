import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { type CryptoKey, exportJWK, generateKeyPair } from 'jose';
import { Provider } from 'oidc-provider';

export const APP_ORIGIN = 'https://app.example.com';

export type TestOidcProvider = {
	issuer: string;
	clientId: string;
	close: () => Promise<void>;
	/**
	 * Follows the authorization request through the provider, signing in as `accountId`, and
	 * returns the URL the provider redirects back to.
	 */
	runAuthorizationFlow: (authorizationUrl: URL, accountId: string) => Promise<URL>;
};

export async function startTestOidcProvider(): Promise<TestOidcProvider> {
	const clientId = 'test-client';

	const server = http.createServer();
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as AddressInfo;
	const issuer = `http://127.0.0.1:${port}`;

	const { privateKey } = await generateKeyPair('RS256', { extractable: true });
	const privateJwk = await exportJWK(privateKey as CryptoKey);

	const provider = new Provider(issuer, {
		cookies: { keys: ['test-only-cookie-key'] },
		jwks: { keys: [{ ...privateJwk, kid: 'test-key', alg: 'RS256', use: 'sig' }] },
		conformIdTokenClaims: false,
		clients: [
			{
				client_id: clientId,
				redirect_uris: [`${APP_ORIGIN}/auth/login-callback`],
				post_logout_redirect_uris: [`${APP_ORIGIN}/auth/logout-callback`],
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
				token_endpoint_auth_method: 'none'
			}
		],
		claims: { openid: ['sub'], email: ['email'] },
		features: {
			introspection: { enabled: true },
			devInteractions: { enabled: false },
			rpInitiatedLogout: { enabled: true }
		},
		async findAccount(_ctx, sub) {
			return { accountId: sub, claims: async () => ({ sub, email: `${sub}@Example.com` }) };
		}
	});

	const oidcCallback = provider.callback();

	server.on('request', async (req, res) => {
		try {
			const url = new URL(req.url ?? '/', issuer);
			const interaction = url.pathname.match(/^\/interaction\/([^/]+)$/);
			if (req.method === 'GET' && interaction) {
				const { prompt, params, session } = await provider.interactionDetails(req, res);
				if (prompt.name === 'login') {
					await provider.interactionFinished(
						req,
						res,
						{ login: { accountId: String(params.login_hint) } },
						{ mergeWithLastSubmission: false }
					);
					return;
				}
				const grant = new provider.Grant({
					accountId: session?.accountId,
					clientId: params.client_id as string
				});
				if (prompt.details.missingOIDCScope) {
					grant.addOIDCScope((prompt.details.missingOIDCScope as string[]).join(' '));
				}
				if (prompt.details.missingOIDCClaims) {
					grant.addOIDCClaims(prompt.details.missingOIDCClaims as string[]);
				}
				await provider.interactionFinished(
					req,
					res,
					{ consent: { grantId: await grant.save() } },
					{ mergeWithLastSubmission: true }
				);
				return;
			}
			await oidcCallback(req, res);
		} catch (err) {
			if (!res.headersSent) {
				res.statusCode = 500;
				res.end(`test oidc provider error: ${(err as Error).message}`);
			}
		}
	});

	async function runAuthorizationFlow(authorizationUrl: URL, accountId: string): Promise<URL> {
		let current = new URL(authorizationUrl);
		current.searchParams.set('login_hint', accountId);
		// oidc-provider only issues a refresh token for offline_access with an explicit consent
		current.searchParams.set('prompt', 'consent');

		const cookies = new Map<string, string>();
		for (let hop = 0; hop < 20; hop++) {
			const cookie = [...cookies].map(([key, value]) => `${key}=${value}`).join('; ');
			const res = await fetch(current, {
				redirect: 'manual',
				headers: cookie ? { cookie } : undefined
			});
			for (const setCookie of res.headers.getSetCookie()) {
				const [pair] = setCookie.split(';');
				const eq = pair.indexOf('=');
				if (eq !== -1) cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
			}

			const location = res.headers.get('location');
			if (res.status < 300 || res.status >= 400 || !location) {
				throw new Error(`unexpected ${res.status} response at ${current}: ${await res.text()}`);
			}
			const next = new URL(location, current);
			if (next.origin === APP_ORIGIN) return next;
			current = next;
		}
		throw new Error('too many redirects while driving the authorization flow');
	}

	return {
		issuer,
		clientId,
		close: () =>
			new Promise<void>((resolve, reject) =>
				server.close((err) => (err ? reject(err) : resolve()))
			),
		runAuthorizationFlow
	};
}
