import { IServiceCollection } from '@telar/core/IServiceCollection';
import { AuthConfigType } from './AuthConfigType';
import { AuthConfig } from './server';

declare module '@telar/core/IServiceCollection' {
    /**
     * Constains extensions for configuring routing
     */
    export interface IServiceCollection {
        /**
         * Add secret into service collection
         */
        addAuth(authConfig: AuthConfig): IServiceCollection;
    }
}

IServiceCollection.prototype.addAuth = function (authConfig: AuthConfig) {
    this.bind(AuthConfigType).toConstantValue(authConfig);
    return this;
};
