// Copyright (c) 2020 Amirhossein Movahedi (@qolzam)
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

import hmacUtils from '@telar/core/utils/hmac-util';
import log from '@telar/core/utils/log-util';
import stringUtils from '@telar/core/utils/string-util';
import securityUtils from '@telar/core/utils/security-util';
import * as http from 'http';
import { Claims } from '@telar/core';

export interface AuthConfig {
    headerCookieName: string;
    payloadCookieName: string;
    signatureCookieName: string;
    publicKey: string;
    payloadSecret: string;
}

export interface AuthCookie {
    header: string;
    payload: string;
    sign: string;
}

export interface UserClaim {
    email: string;
    avatar: string;
    userID: string;
    username: string;
    systemRole: string;
    displayName: string;
}

export interface MetaHMACCookie {
    headers: http.IncomingHttpHeaders;
    body: any;
    payloadSecret: string;
    mustPresentHMAC: boolean;
    cookies: any;
    config: AuthConfig;
    checkAdmin: boolean;
}

export const XCloudSignature = 'X-Cloud-Signature';

function parseClaim(claims: Claims, checkAdmin: boolean): UserClaim {
    const newUserClaim = {} as UserClaim;
    const { role } = claims;
    if (!stringUtils.isEmpty(role)) {
        newUserClaim.systemRole = role;
    }

    if (checkAdmin && role !== 'admin') {
        throw new Error('adminAccessRole');
    }
    const userId = claims.uid;
    log.info('UserID from claims ', userId);
    if (!stringUtils.isEmpty(userId)) {
        newUserClaim.userID = userId;
    }
    const username = claims.email;
    if (!stringUtils.isEmpty(username)) {
        newUserClaim.username = username;
    }
    const { avatar } = claims;
    if (stringUtils.isEmpty(avatar)) {
        newUserClaim.avatar = avatar;
    }
    const { displayName } = claims;
    if (stringUtils.isEmpty(displayName)) {
        newUserClaim.displayName = displayName;
    }

    return newUserClaim;
}

// validateRequest
function validateRequest(body: any, payloadSecret: string, xCloudSignature: string) {
    if (
        xCloudSignature &&
        typeof xCloudSignature === 'string' &&
        hmacUtils.validate(String(body), payloadSecret, xCloudSignature)
    ) {
        return;
    }
    throw new Error('HMAC is not valid!');
}

// hmacProtection check whether hmac header presented
export function hmacProtection(
    headers: http.IncomingHttpHeaders,
    body: any,
    payloadSecret: string,
    mustPresentHMAC: boolean,
) {
    const xCloudSignature = headers[XCloudSignature];
    if (xCloudSignature && typeof xCloudSignature === 'string' && !stringUtils.isEmpty(xCloudSignature)) {
        const authedUser: UserClaim = {} as UserClaim;
        try {
            validateRequest(body, payloadSecret, xCloudSignature);
        } catch (error) {
            log.error('Core: HMAC Error %s', error);
            throw error;
        }
        const userID = headers['uid'];

        if (userID && typeof userID === 'string' && !stringUtils.isEmpty(userID)) {
            authedUser.userID = userID;
        }
        const username = headers['email'];
        if (username && typeof username === 'string' && !stringUtils.isEmpty(username)) {
            authedUser.username = username;
        }
        const avatar = headers['avatar'];
        if (avatar && typeof avatar === 'string' && !stringUtils.isEmpty(avatar)) {
            authedUser.avatar = avatar;
        }
        const displayName = headers['displayName'];
        if (displayName && typeof displayName === 'string' && !stringUtils.isEmpty(displayName)) {
            authedUser.displayName = displayName;
        }
        const systemRole = headers['role'];
        if (systemRole && typeof systemRole === 'string' && !stringUtils.isEmpty(systemRole)) {
            authedUser.systemRole = systemRole;
        }

        return authedUser;
    }

    log.info('Core: HMAC is not presented.');
    if (mustPresentHMAC) {
        throw new Error('HMAC not presented');
    }
    return null;
}

// cookieProtection cookie
export function cookieProtection(cookies: any, config: AuthConfig, checkAdmin: boolean) {
    // Read cookie
    const cookieMap = readCookie(cookies, config);
    // Parse cookie to claim
    const claims = parseClaimFromCookie(cookieMap, config);

    if (!claims) {
        throw new Error(`Claims is null!`);
    }
    // Parse claim to request
    return parseClaim(claims.claim, checkAdmin);
}

// readCookie read cookies in a map
function readCookie(cookies: any, config: AuthConfig): AuthCookie {
    if (!config) {
        throw new Error('Global config is required');
    }
    if (!config.headerCookieName) {
        throw new Error('[headerCookieName] is not apeared in config file');
    }
    const cookieHeader = cookies[config.headerCookieName];
    if (stringUtils.isEmpty(cookieHeader)) {
        throw new Error('Cookie Header not found.');
    }

    if (!config.payloadCookieName) {
        throw new Error('[payloadCookieName] is not apeared in config file');
    }
    const cookiePayload = cookies[config.payloadCookieName];
    if (stringUtils.isEmpty(cookiePayload)) {
        throw new Error('Cookie Payload not found.');
    }

    if (!config.signatureCookieName) {
        throw new Error('[signatureCookieName] is not apeared in config file');
    }
    const cookieSignature = cookies[config.signatureCookieName];
    if (stringUtils.isEmpty(cookieSignature)) {
        throw new Error('Cookie Signature not found.');
    }

    const parsedCookies: AuthCookie = {
        header: cookieHeader,
        payload: cookiePayload,
        sign: cookieSignature,
    };

    return parsedCookies;
}

// parseCookie
function parseClaimFromCookie(
    cookieMap: AuthCookie,
    config: AuthConfig,
): {
    [key: string]: any;
    claim: Claims;
} {
    if (!config.publicKey) {
        throw new Error('[publicKey] is not apeared in config file');
    }
    const keydata = config.publicKey;
    const cookie = `${cookieMap.header}.${cookieMap.payload}.${cookieMap.sign}`;
    return securityUtils.verifyJWT(cookie, keydata);
}
// hmacCookieProtection check protection
export function hmacCookieProtection(meta: MetaHMACCookie) {
    const hmacClaim = hmacProtection(meta.headers, meta.body, meta.payloadSecret, meta.mustPresentHMAC);
    if (hmacClaim === null) {
        cookieProtection(meta.cookies, meta.config, meta.checkAdmin);
    }
    return null;
}
