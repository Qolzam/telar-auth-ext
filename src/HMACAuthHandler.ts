import { METADATA_KEY } from '@telar/core/constants';
import { Context, Next } from '@telar/mvc';
import { AuthConfigType } from './AuthConfigType';
import { AuthConfig, hmacProtection, UserClaim } from './server';
export const HMACAuthHandler = (noErrorIfNotPresented?: boolean) => async (
    ctx: Context<{ user: UserClaim | null }>,
    next: Next,
) => {
    const container = Reflect.getMetadata(METADATA_KEY.httpContext, ctx);
    const authConfig: AuthConfig = container.get(AuthConfigType);
    const userClaim = hmacProtection(ctx.headers, ctx.request.body, authConfig.payloadSecret, !noErrorIfNotPresented);
    ctx.user = userClaim;
    await next();
};
