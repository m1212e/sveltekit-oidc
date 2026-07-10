import type { JWTPayload } from 'jose';
import type { IntrospectionResponse, UserInfoResponse } from 'openid-client';
import { Type, type Static, type TSchema } from 'typebox';
import { Compile } from 'typebox/schema';
import { Value } from 'typebox/value';

const nullable = <T extends TSchema>(t: T) => Type.Optional(Type.Union([Type.Null(), t]));

const OIDCUserSchema = Type.Object({
	sub: Type.String(),
	// email: Type.String({ format: 'email' }),
	email: nullable(Type.String()),
	preferred_username: nullable(Type.String()),
	family_name: nullable(Type.String()),
	given_name: nullable(Type.String()),

	locale: nullable(Type.String()),
	phone: nullable(Type.String())
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = Compile(OIDCUserSchema);
export const parseOIDCUser = (value: unknown) => {
	const v = CompiledOIDCUser.Parse(value);
	// we clean this from excess values to prevent sensitive info
	// which might not be represented by the type schema
	// to be leaked
	// we want to make absolutety sure the type declaration matches the value exactly
	const cleaned = Value.Clean(OIDCUserSchema, { ...v }) as typeof v;

	if (cleaned.email) {
		// normalize email to lowercase to prevent case sensitivity issues
		cleaned.email = String(cleaned.email).toLowerCase();
	}

	return cleaned;
};

const OIDCFlowStateSchema = Type.Object({
	visitedUrl: Type.String(),
	random: Type.String()
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);
export const parseOIDCFlowState = (value: unknown) => CompiledOIDCFlowState.Parse(value);

export type AccessTokenResponse = JWTPayload | IntrospectionResponse | undefined;
export type IdTokenResponse = JWTPayload | IntrospectionResponse | UserInfoResponse | undefined;
export type RefreshTokenResponse = JWTPayload | string | undefined;
export type ValidationResponse = {
	user: OIDCUser;
	accessToken: AccessTokenResponse;
	idToken: IdTokenResponse;
	refreshToken: RefreshTokenResponse;
	/**
	 * Checks whether the session is still live by introspecting the refresh
	 * token (RFC 7662) — read-only, never consumes/rotates it or writes a
	 * cookie. `undefined` when there was no refresh token to check.
	 */
	checkSessionLive?: () => Promise<IntrospectionResponse>;
};
