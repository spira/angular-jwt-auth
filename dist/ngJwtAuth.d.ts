/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module NgJwtAuth {
    interface INgJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): boolean;
        clearToken(): boolean;
        authenticate(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
    }
    interface INgJwtAuthServiceProvider {
        setApiEndpoints(config: IEndpointDefinition): NgJwtAuthServiceProvider;
    }
    interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }
    interface INgJwtAuthServiceConfig {
        tokenLocation: string;
        tokenUser: string;
        loginController: string;
        apiEndpoints: IEndpointDefinition;
    }
    interface IJwtToken {
        header: {
            alg: string;
            typ: string;
        };
        data: {
            iss: string;
            aud: string;
            sub: string;
            nbf?: number;
            iat: number;
            exp: number;
            jti: string;
        };
        signature: string;
    }
}
declare module NgJwtAuth {
    class NgJwtAuthService implements INgJwtAuthService {
        private $http;
        private config;
        constructor(_config: any, _$http: ng.IHttpService);
        private getLoginEndpoint();
        private getTokenExchangeEndpoint();
        private getRefreshEndpoint();
        private static getAuthHeader(username, password);
        private getToken(username, password);
        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        private static readToken(rawToken);
        processNewToken(rawToken: string): boolean;
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        clearToken(): boolean;
        /**
         * Attempt to log in with username and password
         * @param username
         * @param password
         * @returns {IPromise<boolean>}
         */
        authenticate(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
        private getRemoteData(url);
    }
}
declare module NgJwtAuth {
    class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {
        private config;
        constructor();
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        setApiEndpoints(config: IEndpointDefinition): NgJwtAuthServiceProvider;
        $get: (string | (($http: any) => NgJwtAuthService))[];
    }
}
