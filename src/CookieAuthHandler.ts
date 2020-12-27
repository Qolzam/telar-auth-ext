import { METADATA_KEY } from '@telar/core/constants';
import { Context, Next } from '@telar/mvc';
import { AuthConfigType } from './AuthConfigType';
import { AuthConfig, cookieProtection, UserClaim } from './server';
export const CookieAuthHandler = (checkAdmin: boolean) => async (
    ctx: Context<{ user: UserClaim | null }>,
    next: Next,
) => {
    const container = Reflect.getMetadata(METADATA_KEY.httpContext, ctx);
    const authConfig: AuthConfig = container.get(AuthConfigType);
    const userClaim = cookieProtection(ctx.cookies, authConfig, checkAdmin);
    ctx.user = userClaim;
    await next();
};
