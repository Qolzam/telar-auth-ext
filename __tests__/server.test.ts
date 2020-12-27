import HMACUtil from '@telar/core/utils/hmac-util';
import { AuthConfig, cookieProtection, hmacProtection, XCloudSignature } from '../src/server';
import * as fs from 'fs';
import { signJWT } from '@telar/core/utils/security-util';
describe('Server', () => {
    const body = {
        text: 'Hello world!',
    };
    const payloadSecret = 'payload_secret_1235456778';
    const headers = {
        uid: 'userid_123434576587',
        email: 'amir@telar.dev',
        avatar: 'https://util.telar.dev/api/avatars/234234',
        displayName: 'Amir Movhahedi',
        role: 'admin',
    } as any;
    const publicKey = fs.readFileSync('./public.key', 'utf-8');
    const privateKey = fs.readFileSync('./private.key', 'utf-8');
    headers[XCloudSignature] = HMACUtil.sign(JSON.stringify(body), payloadSecret);
    const authConfig: AuthConfig = {
        headerCookieName: 'h',
        payloadCookieName: 'p',
        signatureCookieName: 's',
        publicKey,
        payloadSecret,
    };
    const signedJWT = signJWT(privateKey, headers, 60);
    const splittedSignedJWT = signedJWT.split('.');
    const cookies = {
        [authConfig.headerCookieName]: splittedSignedJWT[0],
        [authConfig.payloadCookieName]: splittedSignedJWT[1],
        [authConfig.signatureCookieName]: splittedSignedJWT[2],
    };
    test('Should valid HMAC', async () => {
        const user = hmacProtection(headers, body, payloadSecret, true);
        expect(user).not.toBe(null);
        if (user) {
            expect(user.userID).toBe(headers.uid);
        }
    });
    test('Should not valid HMAC', async () => {
        const wrongPayloadSecret = 'wrong_payload_secret_1235456778';
        const user = hmacProtection(headers, body, wrongPayloadSecret, true);
        expect(user).not.toBe(null);
        if (user) {
            expect(user.userID).toBe(headers.uid);
        }
    });

    test('Should valid cookie', async () => {
        const user = cookieProtection(cookies, authConfig, true);
        expect(user).not.toBe(null);
        if (user) {
            expect(user.userID).toBe(headers.uid);
        }
    });
});
