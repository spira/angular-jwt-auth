/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module NgJwtAuth {
    interface INgJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): IUser;
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
    interface IUser {
        userId?: any;
        email?: string;
        firstName?: string;
        lastName?: string;
    }
}
declare module NgJwtAuth {
    class NgJwtAuthService implements INgJwtAuthService {
        private $http;
        private $q;
        private config;
        constructor(_config: any, _$http: ng.IHttpService, _$q: ng.IQService);
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
        processNewToken(rawToken: string): IUser;
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
        authenticate(username: string, password: string): ng.IPromise<any>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
        private getRemoteData(url);
        /**
         * Find the user object within the path
         * @todo resolve the return type assignment with _.get
         * @param tokenData
         * @returns {T}
         */
        private getUserFromTokenData(tokenData);
    }
}
declare module NgJwtAuth {
    class Error {
        name: string;
        message: string;
        stack: string;
        constructor(message?: string);
    }
    class NgJwtAuthException extends Error {
        message: string;
        constructor(message: string);
        toString(): string;
    }
    class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {
        private config;
        constructor();
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        setApiEndpoints(config: IEndpointDefinition): NgJwtAuthServiceProvider;
        $get: (string | (($http: any, $q: any) => NgJwtAuthService))[];
    }
}
