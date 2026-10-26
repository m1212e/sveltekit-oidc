# sveltekit-oidc

OpenID Connect sign in for SvelteKit. A thin wrapper around [`@m1212e/oidc`](https://github.com/m1212e/oidc), which does the actual token handling. This package adds the SvelteKit glue: a `handle` hook, cookies and redirects.

```sh
npm i @m1212e/sveltekit-oidc
```

Requires SvelteKit 3 and Node 22.12+ (or Bun).

## Setup

In your `hooks.server.ts`:

```ts
import { makeOIDC } from '@m1212e/sveltekit-oidc';
import { sequence } from '@sveltejs/kit/hooks';

export const OIDC = await makeOIDC({
	issuer: PUBLIC_OIDC_AUTHORITY,
	clientId: PUBLIC_OIDC_CLIENT_ID,
	clientSecret: OIDC_CLIENT_SECRET, // omit for public clients
	authenticatedRoutes: ['/app'],
	async userLoggedInSuccessfully({ user }) {
		await upsertUserAtDatabase(user);
	}
});

export const handle = sequence(OIDC.handle, otherHandler);
```

`OIDC.handle`:

- puts the validated session on `event.locals.oidc` (`{ user, accessTokenClaims, idTokenClaims, tokens }`)
- refreshes expired tokens and writes the new ones back to the cookies
- sends visitors without a session on an `authenticatedRoutes` route to the provider, and back to the page they visited afterwards
- serves the login and logout callback routes, no `+page` files needed
- accepts an `Authorization: Bearer` header when there is no session cookie

Register `<origin>/auth/login-callback` as redirect URI and `<origin>/auth/logout-callback` as post logout redirect URI at your provider.

## Sign out

```ts
const url = await OIDC.getLogoutUrl(event);
redirect(303, url, { external: [url.origin] });
```

The provider sends the browser back to the logout callback route, which clears the session cookies and redirects to `logoutPath`.

## Impersonation

Let a signed in user act as someone else. Obtain tokens for the target through an RFC 8693 token exchange with the user's own token as actor (how you get the subject token is provider specific), then hand them to `startImpersonation`:

```ts
const own = event.locals.oidc!;
const tokens = await OIDC.core.exchangeToken({
	subjectToken, // e.g. from your provider's admin API
	actorToken: own.tokens.accessToken
});
await OIDC.startImpersonation(event, tokens);
```

From then on `event.locals.oidc` describes the impersonated user, and `event.locals.oidc.impersonator` holds the signed in user's own session. `OIDC.stopImpersonation(event)` ends it.

- The tokens must be delegated to the signed in user: the current actor in their `act` claim has to be them. Tokens without `act` (plain impersonation tokens) are refused, so an impersonation always leaves a trace in the token and in `locals.oidc.actors`.
- They are kept in their own cookies, next to the session. Every request checks them against the session, so the impersonation ends when the session ends or changes hands, on sign out and on a new sign in.
- They are never refreshed: the impersonation ends when the exchanged token expires.
- A delegated token is never accepted as a session or bearer token of its own (unless you set the core `delegation` option).
- Who may impersonate whom is up to your app. Check it before the exchange, and again on requests made while impersonating if it can change.

## Options

All [options of `@m1212e/oidc`](https://github.com/m1212e/oidc#options) (`issuer`, `clientId`, `clientSecret`, `expectedAudience`, `development`, `logLevel`, `logger`, ...), plus:

| Option                     | Default                                 |                                                                                         |
| -------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------- |
| `authenticatedRoutes`      | required                                | path prefixes, or `(url: URL) => boolean`                                               |
| `scope`                    | `"openid profile email offline_access"` | requested on sign in                                                                    |
| `loginCallbackRoute`       | `"/auth/login-callback"`                |                                                                                         |
| `logoutCallbackRoute`      | `"/auth/logout-callback"`               |                                                                                         |
| `logoutPath`               | `"/"`                                   | where to go once signed out                                                             |
| `cookiePrefix`             | `"auth_oidc_"`                          | the resulting names are on `OIDC.cookieNames`                                           |
| `sessionMaxAge`            | 30 days                                 | seconds the token cookies live when there is a refresh token                            |
| `allowBearerToken`         | `true`                                  |                                                                                         |
| `userLoggedInSuccessfully` |                                         | called once after sign in, with the session                                             |
| `development`              | `NODE_ENV === "development"`            | also drops the `Secure` flag from the cookies, so signing in works over plain `http://` |

## Other functions

```ts
OIDC.redirectToSignin(event); // start the sign in flow by hand, e.g. from a /login route
OIDC.startImpersonation(event, tokens); // see Impersonation
OIDC.stopImpersonation(event);
OIDC.cookieNames; // { accessToken, idToken, refreshToken, codeVerifier, state, impersonationAccessToken, impersonationIdToken }
OIDC.core; // the underlying @m1212e/oidc instance
```

Everything `@m1212e/oidc` exports (error classes, types such as `OIDCUser`) is re-exported from this package.

## Migrating from 0.0.x

- Options: `oidcAuthority` → `issuer`, `oidcClientId` → `clientId`, `oidcClientSecret` → `clientSecret`, `oidcScope` → `scope`.
- `event.locals.oidc`: `accessToken` → `accessTokenClaims`, `idToken` → `idTokenClaims`, `raw` → `tokens`. `refreshToken` (the decoded refresh token) and `checkSessionLive` are gone.
- `getLogoutUrl(url)` → `getLogoutUrl(event)`. It now sends the id token as `id_token_hint`.
- `validateToken`, `validateTokens`, `isTokenExpired`, `refresh`, `fetchUserInfoFromIssuer`, `startSignin` and `resolveSignin` are gone from the returned object. Use `OIDC.core` instead.
- The default scope now includes `offline_access`.
- The token cookies now outlive the access token when there is a refresh token (see `sessionMaxAge`), so sessions are actually refreshed instead of starting over at the provider.
- The `expires_in`, `scope` and `token_type` cookies are no longer written.

## License

Apache-2.0
