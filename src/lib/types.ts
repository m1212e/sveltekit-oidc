import type { JWTPayload } from 'jose';
import type { IntrospectionResponse, UserInfoResponse } from 'openid-client';
import { Type, type Static, type TSchema } from '@sinclair/typebox';
import { TypeCompiler } from '@sinclair/typebox/compiler';
import { Value } from '@sinclair/typebox/value';

const nullable = <T extends TSchema>(t: T) => Type.Union([Type.Null(), Type.Undefined(), t]);

const OIDCUserSchema = Type.Object({
	sub: Type.String(),
	// email: Type.String({ format: 'email' }),
	email: Type.String(),
	preferred_username: Type.String(),
	family_name: Type.String(),
	given_name: Type.String(),

	locale: nullable(Type.String()),
	phone: nullable(Type.String())
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = TypeCompiler.Compile(OIDCUserSchema);
export const parseOIDCUser = (value: unknown) => {
	const v = CompiledOIDCUser.Decode(value);
	// we clean this from excess values to prevent sensitive info
	// which might not be represented by the type schema
	// to be leaked
	// we want to make absolutety sure the type declaration matches the value exactly
	return Value.Clean(OIDCUserSchema, { ...v }) as typeof v;
};

const OIDCFlowStateSchema = Type.Object({
	visitedUrl: Type.String(),
	random: Type.String()
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = TypeCompiler.Compile(OIDCFlowStateSchema);
export const parseOIDCFlowState = (value: unknown) => CompiledOIDCFlowState.Decode(value);

export type AccessTokenResponse = JWTPayload | IntrospectionResponse | undefined;
export type IdTokenResponse = JWTPayload | IntrospectionResponse | UserInfoResponse | undefined;
export type ValidationResponse = {
	user: OIDCUser;
	accessToken: AccessTokenResponse;
	idToken: IdTokenResponse;
};
