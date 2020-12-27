import { METADATA_KEY } from '@telar/core/constants';
import { Context, Next } from '@telar/mvc';
import { AuthConfigType } from './AuthConfigType';
import { AuthConfig, hmacCookieProtection, MetaHMACCookie, UserClaim } from './server';
export const HMACCookieAuthHandler = (checkAdmin: boolean) => async (
    ctx: Context<{ user: UserClaim | null }>,
    next: Next,
) => {
    const container = Reflect.getMetadata(METADATA_KEY.httpContext, ctx);
    const authConfig: AuthConfig = container.get(AuthConfigType);
    const meta: MetaHMACCookie = {
        headers: ctx.headers,
        body: JSON.stringify(ctx.request.body),
        payloadSecret: authConfig.payloadSecret,
        mustPresentHMAC: false,
        cookies: ctx.cookies,
        config: authConfig,
        checkAdmin: checkAdmin,
    };
    const userClaim = hmacCookieProtection(meta);
    ctx.user = userClaim;
    await next();
};
