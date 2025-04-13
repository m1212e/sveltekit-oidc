import type { JWTPayload } from 'jose';
import type { IntrospectionResponse, UserInfoResponse } from 'openid-client';
import { Type, type Static } from '@sinclair/typebox';
import { TypeCompiler } from '@sinclair/typebox/compiler';

const OIDCUserSchema = Type.Object({
	sub: Type.String(),
	// email: Type.String({ format: 'email' }),
	email: Type.String(),
	preferred_username: Type.String(),
	family_name: Type.String(),
	given_name: Type.String(),

	locale: Type.Optional(Type.String()),
	phone: Type.Optional(Type.String())
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = TypeCompiler.Compile(OIDCUserSchema);
export const parseOIDCUser = CompiledOIDCUser.Decode;

const OIDCFlowStateSchema = Type.Object({
	visitedUrl: Type.String(),
	random: Type.String()
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = TypeCompiler.Compile(OIDCFlowStateSchema);
export const parseOIDCFlowState = CompiledOIDCFlowState.Decode;

export type AccessTokenResponse = JWTPayload | IntrospectionResponse | undefined;
export type IdTokenResponse = JWTPayload | IntrospectionResponse | UserInfoResponse | undefined;
export type ValidationResponse = {
	user: OIDCUser;
	accessToken: AccessTokenResponse;
	idToken: IdTokenResponse;
};
