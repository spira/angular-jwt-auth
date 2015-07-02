/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module NgJwtAuth {
    interface INgJwtAuthService {
        loggedIn: boolean;
        rawToken: string;
        init(): void;
        isLoginMethod(url: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): IUser;
        authenticateCredentials(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireCredentialsAndAuthenticate(): ng.IPromise<Object>;
        registerCredentialPromiseFactory(promiseFactory: ICredentialPromiseFactory): NgJwtAuthService;
        logout(): void;
    }
    interface INgJwtAuthServiceProvider {
        configure(config: INgJwtAuthServiceConfig): NgJwtAuthServiceProvider;
    }
    interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }
    interface INgJwtAuthServiceConfig {
        tokenLocation?: string;
        tokenUser?: string;
        apiEndpoints?: IEndpointDefinition;
        storageKeyName?: string;
        refreshBeforeSeconds?: number;
        checkExpiryEverySeconds?: number;
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
        userId: any;
        email: string;
        firstName?: string;
        lastName?: string;
    }
    interface ICredentials {
        username: string;
        password: string;
    }
    interface ICredentialPromiseFactory {
        (currentUser: IUser): ng.IPromise<ICredentials>;
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
        private $interval;
        private user;
        private credentialPromiseFactory;
        private currentCredentialPromise;
        private refreshTimerPromise;
        private tokenData;
        loggedIn: boolean;
        rawToken: string;
        /**
         * Construct the service with dependencies injected
         * @param _config
         * @param _$http
         * @param _$q
         * @param _$window
         * @param _$interval
         */
        constructor(_config: INgJwtAuthServiceConfig, _$http: ng.IHttpService, _$q: ng.IQService, _$window: ng.IWindowService, _$interval: ng.IIntervalService);
        /**
         * Service needs an init function so runtime configuration can occur before
         * bootstrapping the service. This allows the user supplied CredentialPromiseFactory
         * to be registered
         */
        init(): void;
        /**
         * Handle token refresh timer
         */
        private tickRefreshTime;
        /**
         * Check if the token needs to refresh now
         * @returns {boolean}
         */
        private tokenNeedsToRefreshNow();
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
         * Build a token header string
         * @returns {string}
         */
        private static getTokenHeader(token);
        /**
         * Build a refresh header string
         * @returns {string}
         */
        private getRefreshHeader();
        /**
         * Retrieve the token from the remote API
         * @param endpoint
         * @param authHeader
         * @returns {IPromise<TResult>}
         */
        private retrieveAndProcessToken(endpoint, authHeader);
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
        private loadTokenFromStorage();
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
        /**
         * Clear the token
         */
        private clearJWTToken();
        /**
         * Attempt to log in with username and password
         * @param username
         * @param password
         * @returns {IPromise<boolean>}
         */
        authenticateCredentials(username: string, password: string): ng.IPromise<any>;
        /**
         * Exchange an arbitrary token with a jwt token
         * @param token
         * @returns {ng.IPromise<any>}
         */
        exchangeToken(token: string): ng.IPromise<Object>;
        /**
         * Refresh an existing token
         * @returns {ng.IPromise<any>}
         */
        refreshToken(): ng.IPromise<Object>;
        /**
         * Require that the user logs in again for a request
         * 1. Check if there is already credentials promised
         * 2. If not, execute the credential promise factory
         * 3. Wait until the credentials are resolved
         * 4. Then try to authenticateCredentials
         * @returns {IPromise<TResult>}
         */
        requireCredentialsAndAuthenticate(): ng.IPromise<IUser>;
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
        /**
         * Remove the default http authorization header
         */
        private unsetJWTHeader();
        /**
         * Handle a request that was rejected due to unauthorised response
         * 1. Require authentication
         * 2. Retry the rejected $http request
         *
         * @param rejection
         */
        handleInterceptedUnauthorisedResponse(rejection: any): void;
        /**
         * Register the user provided credential promise factory
         * @param promiseFactory
         */
        registerCredentialPromiseFactory(promiseFactory: ICredentialPromiseFactory): NgJwtAuthService;
        /**
         * Clear the token and service properties
         */
        logout(): void;
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
    class NgJwtAuthTokenExpiredException extends NgJwtAuthException {
    }
    class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {
        private config;
        /**
         * Initialise the service provider
         */
        constructor();
        /**
         * Set the configuration
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        configure(config: IEndpointDefinition): NgJwtAuthServiceProvider;
        $get: (string | (($http: any, $q: any, $window: any, $interval: any) => NgJwtAuthService))[];
    }
}
