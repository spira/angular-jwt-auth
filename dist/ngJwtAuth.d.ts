/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module NgJwtAuth {
    interface INgJwtAuthService {
        loggedIn: boolean;
        isLoginMethod(url: string): boolean;
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
        storageKeyName: string;
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
    class NgJwtAuthInterceptor {
        private $http;
        private $q;
        private $injector;
        private ngJwtAuthService;
        /**
         * Construct the service with dependencies injected
         * @param _$q
         * @param _$injector
         */
        static $inject: string[];
        constructor(_$q: ng.IQService, _$injector: ng.auto.IInjectorService);
        private getNgJwtAuthService;
        responseError: (rejection: any) => any;
    }
}
declare module NgJwtAuth {
    class NgJwtAuthService implements INgJwtAuthService {
        private config;
        private $http;
        private $q;
        private $window;
        loggedIn: boolean;
        private user;
        /**
         * Construct the service with dependencies injected
         * @param _config
         * @param _$http
         * @param _$q
         * @param _$window
         */
        constructor(_config: any, _$http: ng.IHttpService, _$q: ng.IQService, _$window: ng.IWindowService);
        /**
         * Get the endpoint for login
         * @returns {string}
         */
        private getLoginEndpoint();
        /**
         * Get the endpoint for exchanging a token
         * @returns {string}
         */
        private getTokenExchangeEndpoint();
        /**
         * Get the endpoint for refreshing a token
         * @returns {string}
         */
        private getRefreshEndpoint();
        /**
         * Build a authentication basic header string
         * @param username
         * @param password
         * @returns {string}
         */
        private static getAuthHeader(username, password);
        /**
         * Retrieve the token from the remote API
         * @param username
         * @param password
         * @returns {IPromise<TResult>}
         */
        private getToken(username, password);
        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        private static readToken(rawToken);
        /**
         * Read and save the raw token to storage, kick off timer to attempt refresh
         * @param rawToken
         * @returns {IUser}
         */
        processNewToken(rawToken: string): IUser;
        /**
         * Check if the endpoint is a login method (used for skipping the authentication error interceptor)
         * @param url
         * @returns {boolean}
         */
        isLoginMethod(url: string): boolean;
        getUser(): IUser;
        /**
         *
         * @returns {IHttpPromise<T>}
         */
        getPromisedUser(): ng.IPromise<IUser>;
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
        /**
         * Find the user object within the path
         * @todo resolve the return type assignment with _.get
         * @param tokenData
         * @returns {T}
         */
        private getUserFromTokenData(tokenData);
        /**
         * Save the token
         * @param rawToken
         */
        private saveTokenToStorage(rawToken);
        /**
         * Set the authentication token for all new requests
         * @param rawToken
         */
        private setJWTHeader(rawToken);
        handleInterceptedUnauthorisedResponse(rejection: any): void;
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
        $get: (string | (($http: any, $q: any, $window: any) => NgJwtAuthService))[];
    }
}
