import { randomBytes } from "node:crypto";
import { dev } from "$app/environment";
import { type RequestEvent, error, redirect } from "@sveltejs/kit";
import Cryptr from "cryptr";
import { createRemoteJWKSet, jwtVerify } from "jose";
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
	tokenIntrospection,
} from "openid-client";
import { z } from "zod";
import { makeCookieNames } from "./cookie";
import { type OIDCFlowState, type OIDCUser, isValidOIDCUser } from "./types";

export async function makeOIDC({
	development = dev,
	oidcAuthority,
	oidcClientId,
	oidcClientSecret,
	secret,
	oidcScope,
	logoutPath = "/",
	cookiePrefix,
	userLoggedInSuccessfully,
	loginCallbackRoute = "/auth/login-callback",
	logoutCallbackRoute = "/auth/logout-callback",
}: {
	development?: boolean;
	oidcAuthority: string;
	oidcClientId: string;
	oidcClientSecret?: string;
	secret?: string;
	oidcScope?: string;
	logoutPath?: string;
	cookiePrefix?: string;
	userLoggedInSuccessfully?: (user: OIDCUser) => Promise<void> | void;
	loginCallbackRoute?: string;
	logoutCallbackRoute?: string;
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
			token_endpoint_auth_method: oidcClientSecret ? undefined : "none",
		},
		undefined,
		{
			execute,
		},
	);

	const jwks_uri = config.serverMetadata().jwks_uri;
	const jwks = jwks_uri
		? await createRemoteJWKSet(new URL(jwks_uri))
		: undefined;

	const cryptr = new Cryptr(secret ?? randomBytes(100).toString("hex"));

	const {
		accessTokenCookieName,
		codeVerifierCookieName,
		expiresInCookieName,
		idTokenCookieName,
		oidcStateCookieName,
		refreshTokenCookieName,
		scopeCookieName,
		tokenTypeCookieName,
	} = makeCookieNames(cookiePrefix);

	async function startSignin(visitedUrl: URL) {
		const code_verifier = randomPKCECodeVerifier();
		const encrypted_verifier = cryptr.encrypt(code_verifier);
		const code_challenge = await calculatePKCECodeChallenge(code_verifier);
		const state: OIDCFlowState = {
			visitedUrl: visitedUrl.toString(),
			random: randomState(),
		};
		const serialized_state = JSON.stringify(state);
		const encrypted_state = cryptr.encrypt(serialized_state);

		const parameters: Record<string, string> = {
			redirect_uri: `${visitedUrl.origin}/auth/login-callback`,
			scope: oidcScope ?? "openid profile email",
			code_challenge,
			code_challenge_method: "S256",
			state: serialized_state,
		};

		const redirect_uri = buildAuthorizationUrl(config, parameters);

		return {
			encrypted_verifier,
			redirect_uri,
			encrypted_state,
		};
	}

	async function resolveSignin(
		visitedUrl: URL,
		encrypted_verifier: string,
		encrypted_state: string,
	) {
		const verifier = cryptr.decrypt(encrypted_verifier);
		const state = JSON.parse(cryptr.decrypt(encrypted_state)) as OIDCFlowState;
		const tokens = await authorizationCodeGrant(config, visitedUrl, {
			pkceCodeVerifier: verifier,
			expectedState: JSON.stringify(state),
		});
		(state as any).random = undefined;
		const strippedState: Omit<OIDCFlowState, "random"> = { ...state };

		return { tokens, state: strippedState };
	}

	async function validateTokens({
		access_token,
		id_token,
	}: Pick<
		TokenEndpointResponse,
		"access_token" | "id_token"
	>): Promise<OIDCUser> {
		try {
			if (!jwks) throw new Error("No jwks available");
			const keyset = await jwks();
			if (!keyset) throw new Error("No jwks available");
			if (!id_token) throw new Error("No id_token available");

			const [accessTokenValue, idTokenValue] = await Promise.all([
				jwtVerify(access_token, keyset, {
					issuer: config.serverMetadata().issuer,
					audience: oidcClientId,
				}),
				jwtVerify(id_token, keyset, {
					issuer: config.serverMetadata().issuer,
					audience: oidcClientId,
				}),
			]);

			if (accessTokenValue?.payload?.sub !== idTokenValue?.payload?.sub) {
				throw new Error("Subject in access token and id token do not match");
			}

			// some basic fields which we want to be present
			// if the id token is configured in a way that it does not contain these fields
			// we instead want to use the userinfo endpoint
			if (!isValidOIDCUser(idTokenValue.payload)) {
				throw new Error("Not all fields in id token are present");
			}

			return idTokenValue.payload;
		} catch (error: any) {
			console.warn(
				"Failed to verify tokens locally, falling back to less performant info fetch:",
				error.message,
			);

			const remoteUserInfo = await tokenIntrospection(config, access_token);

			if (!isValidOIDCUser(remoteUserInfo)) {
				throw new Error("Not all fields in remoteUserInfo token are present");
			}

			return remoteUserInfo;
		}
	}

	async function refresh(refresh_token: string) {
		return refreshTokenGrant(config, refresh_token);
	}

	async function getLogoutUrl(visitedUrl: URL) {
		return buildEndSessionUrl(config, {
			post_logout_redirect_uri: `${visitedUrl.origin}${logoutPath}`,
		});
	}

	async function fetchUserInfoFromIssuer(
		access_token: string,
		expectedSubject: string,
	) {
		return fetchUserInfo(config, access_token, expectedSubject);
	}

	async function handleLoginRedirect(req: RequestEvent) {
		const verifier = req.cookies.get(codeVerifierCookieName);
		if (!verifier) error(400, "No code verifier cookie found.");
		const oidcState = req.cookies.get(oidcStateCookieName);
		if (!oidcState) error(400, "No oidc state cookie found.");

		const { state, tokens } = await resolveSignin(req.url, verifier, oidcState);

		setTokenCookiesOnRequest(req, tokens);

		req.cookies.delete(codeVerifierCookieName, { path: "/" });
		req.cookies.delete(oidcStateCookieName, { path: "/" });

		const user = await validateTokens(tokens);
		await userLoggedInSuccessfully?.(user);

		return redirect(302, state.visitedUrl);
	}

	function setTokenCookiesOnRequest(
		req: RequestEvent,
		tokens: TokenEndpointResponse & TokenEndpointResponseHelpers,
	) {
		const cookieOptions: Parameters<typeof req.cookies.set>[2] = {
			path: "/",
			httpOnly: true,
			// sameSite: 'lax',
			sameSite: "strict",
			secure: true,
			maxAge: tokens.expires_in ? tokens.expires_in * 1000 : undefined,
		};

		req.cookies.set(accessTokenCookieName, tokens.access_token, cookieOptions);
		if (tokens.refresh_token) {
			req.cookies.set(
				refreshTokenCookieName,
				tokens.refresh_token,
				cookieOptions,
			);
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
		req.cookies.delete(codeVerifierCookieName, { path: "/" });
		req.cookies.delete(oidcStateCookieName, { path: "/" });
		req.cookies.delete(accessTokenCookieName, { path: "/" });
		req.cookies.delete(refreshTokenCookieName, { path: "/" });
		req.cookies.delete(idTokenCookieName, { path: "/" });
		req.cookies.delete(expiresInCookieName, { path: "/" });
		req.cookies.delete(scopeCookieName, { path: "/" });
		req.cookies.delete(tokenTypeCookieName, { path: "/" });

		return redirect(303, "/");
	}

	async function handle({
		event,
		authenticatedRoutes,
	}: {
		event: RequestEvent;
		authenticatedRoutes: string[];
	}) {
		if (event.url.pathname.startsWith(loginCallbackRoute)) {
			return handleLoginRedirect(event);
		}

		if (event.url.pathname.startsWith(logoutCallbackRoute)) {
			return handleLogoutRedirect(event);
		}

		try {
			const accessToken = event.cookies.get(accessTokenCookieName);
			const idToken = event.cookies.get(idTokenCookieName);
			if (!accessToken) {
				throw new Error("No access token found");
			}
			const user = await validateTokens({
				access_token: accessToken,
				id_token: idToken,
			});

			event.locals.user = user;
			return user;
		} catch (error) {
			const refreshToken = event.cookies.get(refreshTokenCookieName);
			if (refreshToken) {
				try {
					const newTokenSet = await refresh(refreshToken);
					setTokenCookiesOnRequest(event, newTokenSet);
					return await validateTokens(newTokenSet);
				} catch (error) {
					// console.warn('Error refreshing token', error);
				}
			}

			// if neither validation nor refresh worked, start login flow
			// but only if a route is protected
			if (
				!authenticatedRoutes
					.map((r) => event.url.pathname.startsWith(r))
					.some(Boolean)
			) {
				return;
			}

			const { encrypted_state, encrypted_verifier, redirect_uri } =
				await startSignin(event.url);

			event.cookies.set(codeVerifierCookieName, encrypted_verifier, {
				sameSite: "lax",
				maxAge: 60 * 5,
				path: "/",
				secure: true,
				httpOnly: true,
			});

			event.cookies.set(oidcStateCookieName, encrypted_state, {
				sameSite: "lax",
				maxAge: 60 * 5,
				path: "/",
				secure: true,
				httpOnly: true,
			});

			throw redirect(302, redirect_uri);
		}
	}

	return {
		handle,
		fetchUserInfoFromIssuer,
		getLogoutUrl,
	};
}
