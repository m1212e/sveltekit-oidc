# svletekit-oidc

Implementing OIDC with Sveltekit never has been easier:

In your `hooks.server.ts`

```ts
import { sequence } from '@sveltejs/kit/hooks';

export const OIDC = await makeOIDC({
	oidcAuthority: PUBLIC_OIDC_AUTHORITY,
	oidcClientId: PUBLIC_OIDC_CLIENT_ID,
	secret: OIDC_CLIENT_SECRET,
	authenticatedRoutes: ['/app'],
	async userLoggedInSuccessfully(user) {
		upsertUserAtDatabase();
	}
});

export const handle: Handle = sequence(OIDC.handle, otherHandler);
```

Now the user is available via the locals on your server.
