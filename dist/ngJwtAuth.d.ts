/// <reference path="../typings/tsd.d.ts" />
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
        response: (response: ng.IHttpPromiseCallbackArg<any>) => ng.IHttpPromiseCallbackArg<any>;
        responseError: (rejection: any) => any;
    }
}
declare module NgJwtAuth {
    interface INgJwtAuthService {
        loggedIn: boolean;
        rawToken: string;
        getConfig(): INgJwtAuthServiceConfig;
        init(): void;
        isLoginMethod(url: string): boolean;
        promptLogin(): ng.IPromise<Object>;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): ng.IPromise<IUser>;
        loginAsUser(userIdentifier: string | number): ng.IPromise<IUser>;
        authenticateCredentials(username: string, password: string): ng.IPromise<Object>;
        validateToken(rawToken: string): boolean;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireCredentialsAndAuthenticate(): ng.IPromise<Object>;
        registerLoginPromptFactory(promiseFactory: ILoginPromptFactory): NgJwtAuthService;
        registerUserFactory(userFactory: IUserFactory): NgJwtAuthService;
        logout(): void;
    }
    interface INgJwtAuthServiceProvider {
        configure(config: INgJwtAuthServiceConfig): NgJwtAuthServiceProvider;
    }
    interface IEndpointDefinition {
        base?: string;
        login?: string;
        loginAsUser?: string;
        tokenExchange?: string;
        refresh?: string;
    }
    interface ICookieConfig {
        enabled: boolean;
        name?: string;
        topLevelDomain?: boolean;
    }
    interface INgJwtAuthServiceConfig {
        tokenLocation?: string;
        tokenUser?: string;
        apiEndpoints?: IEndpointDefinition;
        storageKeyName?: string;
        refreshBeforeSeconds?: number;
        checkExpiryEverySeconds?: number;
        cookie?: ICookieConfig;
    }
    interface IJwtClaims {
        iss: string;
        aud: string;
        sub: string;
        nbf?: number;
        iat: number;
        exp: number;
        jti: string;
    }
    interface IJwtToken {
        header: {
            alg: string;
            typ: string;
        };
        data: IJwtClaims;
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
    interface ILoginPromptFactory {
        (deferredCredentials: ng.IDeferred<ICredentials>, loginSuccessPromise: ng.IPromise<IUser>, currentUser: IUser): ng.IPromise<any>;
    }
    interface IUserFactory {
        (subClaim: string, tokenData: IJwtClaims): ng.IPromise<IUser>;
    }
    interface ILoginListener {
        (user: IUser): any;
    }
    interface IBase64Service {
        encode(string: string): string;
        decode(string: string): string;
        urldecode(string: string): string;
        urldecode(string: string): string;
    }
}
declare module NgJwtAuth {
    class NgJwtAuthService implements INgJwtAuthService {
        private config;
        private $http;
        private $q;
        private $window;
        private $interval;
        private base64Service;
        private $cookies;
        private $location;
        private userFactory;
        private loginPromptFactory;
        private loginListeners;
        private userLoggedInPromise;
        private refreshTimerPromise;
        private tokenData;
        user: IUser;
        loggedIn: boolean;
        rawToken: string;
        /**
         * Construct the service with dependencies injected
         * @param config
         * @param $http
         * @param $q
         * @param $window
         * @param $interval
         * @param base64Service
         * @param $cookies
         * @param $location
         */
        constructor(config: INgJwtAuthServiceConfig, $http: ng.IHttpService, $q: ng.IQService, $window: ng.IWindowService, $interval: ng.IIntervalService, base64Service: IBase64Service, $cookies: ng.cookies.ICookiesService, $location: ng.ILocationService);
        /**
         * Get the current configuration
         * @returns {INgJwtAuthServiceConfig}
         */
        getConfig(): INgJwtAuthServiceConfig;
        /**
         * A default implementation of the user factory if the client does not provide one
         */
        private defaultUserFactory(subClaim, tokenData);
        /**
         * Service needs an init function so runtime configuration can occur before
         * bootstrapping the service. This allows the user supplied LoginPromptFactory
         * to be registered
         */
        init(): ng.IPromise<boolean>;
        /**
         * Register the refresh timer
         */
        private startRefreshTimer();
        /**
         * Cancel the refresh timer
         */
        private cancelRefreshTimer();
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
         * Get the endpoint for getting a user's token (impersonation)
         * @returns {string}
         */
        private getLoginAsUserEndpoint(userIdentifier);
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
         * Get the standard header for a jwt token request
         * @returns {string}
         */
        private getBearerHeader();
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
        private readToken(rawToken);
        /**
         * Validate JWT Token
         * @param rawToken
         * @returns {any}
         */
        validateToken(rawToken: string): boolean;
        /**
         * Prompt user for their login credentials, and attempt to login
         * @returns {ng.IPromise<IUser>}
         */
        promptLogin(): angular.IPromise<Object>;
        /**
         * Read and save the raw token to storage, kick off timer to attempt refresh
         * @param rawToken
         * @returns {IUser}
         */
        processNewToken(rawToken: string): ng.IPromise<IUser>;
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
        authenticateCredentials(username: string, password: string): ng.IPromise<IUser>;
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
         * Handle the login event
         * @param user
         */
        private handleLogin(user);
        /**
         * Find the user object within the path
         * @param tokenData
         * @returns {T}
         */
        private getUserFromTokenData(tokenData);
        /**
         * Save the token
         * @param rawToken
         * @param tokenData
         */
        private saveTokenToStorage(rawToken, tokenData);
        /**
         * Save to cookie
         * @param rawToken
         * @param tokenData
         */
        private saveCookie(rawToken, tokenData);
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
        handleInterceptedUnauthorisedResponse(rejection: ng.IHttpPromiseCallbackArg): ng.IPromise<ng.IHttpPromise<any>>;
        /**
         * Register the login prompt factory
         * @param loginPromptFactory
         * @returns {NgJwtAuth.NgJwtAuthService}
         */
        registerLoginPromptFactory(loginPromptFactory: ILoginPromptFactory): NgJwtAuthService;
        /**
         * Register the user factory for extracting a user from data
         * @param userFactory
         * @returns {NgJwtAuth.NgJwtAuthService}
         */
        registerUserFactory(userFactory: IUserFactory): NgJwtAuthService;
        /**
         * Clear the token and service properties
         */
        logout(): void;
        /**
         * Register a login listener function
         * @param loginListener
         */
        registerLoginListener(loginListener: ILoginListener): void;
        /**
         * Get a user's token given their identifier
         * @param userIdentifier
         * @returns {ng.IPromise<IUser>}
         *
         * Note this feature should be implemented very carefully as it is a security risk as it means users
         * can log in as other users (impersonation). The responsibility is on the implementing app to strongly
         * control permissions to access this endpoint to avoid security risks
         */
        loginAsUser(userIdentifier: string | number): ng.IPromise<IUser>;
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
    class NgJwtAuthCredentialsFailedException extends NgJwtAuthException {
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
        $get: (string | (($http: any, $q: any, $window: any, $interval: any, base64: any, $cookies: any, $location: any) => NgJwtAuthService))[];
    }
}
