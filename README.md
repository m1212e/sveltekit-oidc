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

## Logging

By default the library logs `warn` and `error` messages via `console`. You can control this with two options on `makeOIDC`:

**`logLevel`** — tune the built-in console logger:

```ts
export const OIDC = await makeOIDC({
	// ...
	logLevel: 'debug' // 'silent' | 'error' | 'warn' | 'info' | 'debug'
});
```

**`logger`** — inject your own logger (any object with `debug / info / warn / error` methods). When set, `logLevel` is ignored.

```ts
// Pass the browser/Node console directly:
export const OIDC = await makeOIDC({ ..., logger: console });

// Or adapt pino:
import pino from 'pino';
const pinoLogger = pino();
export const OIDC = await makeOIDC({ ..., logger: pinoLogger });

// Or adapt winston:
import { createLogger, transports } from 'winston';
const winstonLogger = createLogger({ transports: [new transports.Console()] });
export const OIDC = await makeOIDC({ ..., logger: winstonLogger });
```

The `Logger` and `LogLevel` types are exported from the package for type-safe adapters:

```ts
import type { Logger } from '@m1212e/sveltekit-oidc';
```
