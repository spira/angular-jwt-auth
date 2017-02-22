import * as moment from "moment";
import * as _ from "lodash";

import {
    IUserFactory,
    ILoginPromptFactory,
    IUserEventListener,
    IJwtToken,
    IUser,
    INgJwtAuthServiceConfig,
    IBase64Service,
    IJwtClaims, ICredentials,
} from "../ngJwtAuthInterfaces";

import {
    NgJwtAuthException, NgJwtAuthCredentialsFailedException,
    NgJwtAuthTokenExpiredException
} from "../provider/ngJwtAuthServiceProvider";

export class NgJwtAuthService {

    //private properties
    private userFactory:IUserFactory;
    private loginPromptFactory:ILoginPromptFactory;
    private loginListeners:IUserEventListener[] = [];
    private logoutListeners:IUserEventListener[] = [];
    private userLoggedInPromise:ng.IPromise<any>;

    private refreshTimerPromise:ng.IPromise<any>;
    private tokenData:IJwtToken;

    //public properties
    public user:IUser;
    public loggedIn:boolean = false;
    public rawToken:string;

    /**
     * Construct the service with dependencies injected.
     * @param config
     * @param $http
     * @param $q
     * @param $window
     * @param $interval
     * @param base64Service
     * @param $cookies
     * @param $location
     */
    constructor(private config:INgJwtAuthServiceConfig,
                private $http:ng.IHttpService,
                private $q:ng.IQService,
                private $window:ng.IWindowService,
                private $interval:ng.IIntervalService,
                private base64Service:IBase64Service,
                private $cookies:ng.cookies.ICookiesService,
                private $location:ng.ILocationService) {

        this.userFactory = this.defaultUserFactory;

    }

    /**
     * Get the current configuration
     * @returns {INgJwtAuthServiceConfig}
     */
    public getConfig():INgJwtAuthServiceConfig {
        return this.config;
    }

    /**
     * A default implementation of the user factory if the client does not provide one
     */
    private defaultUserFactory(subClaim:string, tokenData:IJwtClaims):ng.IPromise<IUser> {

        return this.$q.when(_.get(tokenData, this.config.tokenUser));
    }

    /**
     * Service needs an init function so runtime configuration can occur before
     * bootstrapping the service. This allows the user supplied LoginPromptFactory
     * to be registered
     */
    public init():ng.IPromise<boolean> {

        //attempt to load the token from storage
        return this.loadTokenFromStorage()
            .then(() => {
                this.startRefreshTimer();
                return true;
            });

    }

    /**
     * Register the refresh timer
     */
    private startRefreshTimer() {
        //if the timer is already set, clear it so the timing is reset
        if (!!this.refreshTimerPromise) {
            this.cancelRefreshTimer();
        }
        this.refreshTimerPromise = this.$interval(this.tickRefreshTime, this.config.checkExpiryEverySeconds * 1000, null, false);
    }

    /**
     * Cancel the refresh timer
     */
    private cancelRefreshTimer():void {
        this.$interval.cancel(this.refreshTimerPromise);
        this.refreshTimerPromise = null;
    }

    /**
     * Handle token refresh timer
     */
    private tickRefreshTime = ():void => {

        if (!this.userLoggedInPromise && this.tokenNeedsToRefreshNow()) {
            this.refreshToken();
        }

    };

    /**
     * Check if the token needs to refresh now
     * @returns {boolean}
     */
    private tokenNeedsToRefreshNow():boolean {

        if (!this.rawToken) {
            return false; //cant refresh if there isn't a token
        }

        let latestRefresh = moment(this.tokenData.data.exp * 1000).subtract(this.config.refreshBeforeSeconds, 'seconds'),
            nextRefreshOpportunity = moment().add(this.config.checkExpiryEverySeconds)
            ;

        //needs to refresh if the the next time we could refresh is after the configured refresh before date
        return (latestRefresh <= nextRefreshOpportunity);
    }

    /**
     * Get the endpoint for login
     * @returns {string}
     */
    private getLoginEndpoint():string {
        return this.config.apiEndpoints.base + this.config.apiEndpoints.login;
    }

    /**
     * Get the endpoint for exchanging a token
     * @returns {string}
     */
    private getTokenExchangeEndpoint():string {
        return this.config.apiEndpoints.base + this.config.apiEndpoints.tokenExchange;
    }

    /**
     * Get the endpoint for getting a user's token (impersonation)
     * @returns {string}
     */
    private getLoginAsUserEndpoint(userIdentifier:string|number):string {
        return this.config.apiEndpoints.base + this.config.apiEndpoints.loginAsUser + '/' + userIdentifier;
    }

    /**
     * Get the endpoint for refreshing a token
     * @returns {string}
     */
    private getRefreshEndpoint():string {
        return this.config.apiEndpoints.base + this.config.apiEndpoints.refresh;
    }

    /**
     * Build a authentication basic header string
     * @param username
     * @param password
     * @returns {string}
     */
    private static getAuthHeader(username:string, password:string):string {
        return 'Basic ' + btoa(username + ':' + password); //note btoa is NOT supported <= IE9
    }

    /**
     * Build a token header string
     * @returns {string}
     */
    private static getTokenHeader(token:string):string {
        return 'Token ' + token;
    }

    /**
     * Get the standard header for a jwt token request
     * @returns {string}
     */
    private getBearerHeader():string {
        if (!this.rawToken) {
            throw new NgJwtAuthException("Token is not set");
        }

        return 'Bearer ' + this.rawToken;
    }

    /**
     * Build a refresh header string
     * @returns {string}
     */
    private getRefreshHeader():string {
        if (!this.rawToken) {
            throw new NgJwtAuthException("Token is not set, it cannot be refreshed");
        }

        return 'Bearer ' + this.rawToken;
    }

    /**
     * Retrieve the token from the remote API
     * @param endpoint
     * @param authHeader
     * @returns {IPromise<IUser>}
     */
    private retrieveAndProcessToken(endpoint:string, authHeader:string):ng.IPromise<IUser> {

        let requestConfig:ng.IRequestConfig = {
            method: 'GET',
            url: endpoint,
            headers: {
                Authorization: authHeader
            },
            responseType: 'json'
        };

        return this.$http(requestConfig).then((result:ng.IHttpPromiseCallbackArg<any>) => {

                if (result && result.data) {
                    let token = _.get(result.data, this.config.tokenLocation);

                    if (_.isString(token)) {
                        return token;
                    }
                }

                return this.$q.reject(new NgJwtAuthException("Token could not be found in response body"));
            })
            .then((token:string) => {

                try {

                    return this.processNewToken(token);

                } catch (error) {
                    return this.$q.reject(error);
                }

            })
            .catch((e:any) => {

                if (_.isError(e) || e instanceof (<any>this.$window).Error) {
                    return this.$q.reject(new NgJwtAuthException(e.message));
                }

                if (e.status === 401) {

                    return this.$q.reject(new NgJwtAuthCredentialsFailedException("Login attempt received unauthorised response"));
                }

                return this.$q.reject(new NgJwtAuthException("The API reported an error - " + e.status + " " + e.statusText));
            })

    }

    /**
     * Parse the raw token
     * @param rawToken
     * @returns {IJwtToken}
     */
    private readToken(rawToken:string):IJwtToken {

        if ((rawToken.match(/\./g) || []).length !== 2) {
            throw new NgJwtAuthException("Raw token is has incorrect format. Format must be of form \"[header].[data].[signature]\"");
        }

        let pieces = rawToken.split('.');

        let jwt:IJwtToken = {
            header: angular.fromJson(this.base64Service.urldecode(pieces[0])),
            data: angular.fromJson(this.base64Service.urldecode(pieces[1])),
            signature: pieces[2],
        };

        return jwt;
    }

    /**
     * Validate JWT Token
     * @param rawToken
     * @returns {any}
     */
    public validateToken(rawToken:string):boolean {

        try {
            let tokenData = this.readToken(rawToken);

            return _.isObject(tokenData);

        } catch (e) {
            return false;
        }

    }

    /**
     * Prompt user for their login credentials, and attempt to login
     * @returns {ng.IPromise<IUser>}
     */
    public promptLogin():angular.IPromise<Object> {

        return this.requireCredentialsAndAuthenticate();
    }

    /**
     * Read and save the raw token to storage, kick off timer to attempt refresh
     * @param rawToken
     * @returns {IUser}
     */
    public processNewToken(rawToken:string):ng.IPromise<IUser> {

        this.rawToken = rawToken;

        this.tokenData = this.readToken(rawToken);

        if (this.tokenHasExpired()) {
            throw new NgJwtAuthTokenExpiredException("Token has expired");
        }

        this.saveTokenToStorage(rawToken, this.tokenData);

        this.setJWTHeader(rawToken);

        this.loggedIn = true;

        this.startRefreshTimer();

        let userFromToken = this.getUserFromTokenData(this.tokenData);

        userFromToken.then((user) => this.handleLogin(user));

        return userFromToken;
    }

    private loadTokenFromStorage():ng.IPromise<IUser|String> {

        let rawToken = this.$window.localStorage.getItem(this.config.storageKeyName);

        if (!rawToken) {
            return this.$q.when("No token in storage");
        }

        try {
            return this.processNewToken(rawToken);
        } catch (e) {
            if (e instanceof NgJwtAuthTokenExpiredException) {
                return this.requireCredentialsAndAuthenticate();
            }

            return this.$q.reject(e);

        }

    }

    /**
     * Check if the endpoint is a login method (used for skipping the authentication error interceptor)
     * @param url
     * @returns {boolean}
     */
    public isLoginMethod(url:string):boolean {

        let loginMethods = [
            this.getLoginEndpoint(),
            this.getTokenExchangeEndpoint(),
        ];

        return _.includes(loginMethods, url);
    }

    public getUser():IUser {
        return this.user;
    }

    /**
     *
     * @returns {IHttpPromise<IUser>}
     */
    public getPromisedUser():ng.IPromise<IUser> {

        if (this.loggedIn) { //if we are already logged in, resolve the user immediately
            return this.$q.when(this.user);
        } else { //otherwise require login then return the user
            return this.requireCredentialsAndAuthenticate();
        }

    }

    /**
     * Clear the token
     */
    private clearJWTToken():void {
        this.rawToken = null;
        this.$window.localStorage.removeItem(this.config.storageKeyName);

        if (this.config.cookie.enabled) {

            this.$cookies.remove(this.config.cookie.name);
        }

        this.unsetJWTHeader();
    }

    /**
     * Attempt to log in with username and password
     * @param username
     * @param password
     * @returns {IPromise<boolean>}
     */
    public authenticateCredentials(username:string, password:string):ng.IPromise<IUser> {

        let authHeader = NgJwtAuthService.getAuthHeader(username, password);
        let endpoint = this.getLoginEndpoint();

        return this.retrieveAndProcessToken(endpoint, authHeader);

    }

    /**
     * Exchange an arbitrary token with a jwt token
     * @param token
     * @returns {ng.IPromise<any>}
     */
    public exchangeToken(token:string):ng.IPromise<Object> {

        let authHeader = NgJwtAuthService.getTokenHeader(token);
        let endpoint = this.getTokenExchangeEndpoint();

        return this.retrieveAndProcessToken(endpoint, authHeader);
    }

    /**
     * Refresh an existing token
     * @returns {ng.IPromise<any>}
     */
    public refreshToken():ng.IPromise<Object> {

        let authHeader = this.getRefreshHeader();
        let endpoint = this.getRefreshEndpoint();

        return this.retrieveAndProcessToken(endpoint, authHeader)
            .catch((err) => {
                this.cancelRefreshTimer(); //if token refreshing fails, stop the refresh timer
                return this.$q.reject(err);
            });

    }

    /**
     * Require that the user logs in again for a request
     * 1. Check if there is already credentials promised
     * 2. If not, execute the credential promise factory
     * 3. Wait until the credentials are resolved
     * 4. Then try to authenticateCredentials
     * @returns {IPromise<IUser>}
     */
    public requireCredentialsAndAuthenticate():ng.IPromise<IUser> {

        if (!_.isFunction(this.loginPromptFactory)) {
            throw new NgJwtAuthException("You must set a loginPromptFactory with `ngJwtAuthService.registerLoginPromptFactory()` so the user can be prompted for their credentials");
        }

        if (!this.userLoggedInPromise) {
            let deferredCredentials = this.$q.defer();

            let loginSuccess = this.$q.defer();

            deferredCredentials.promise
                .then(null, null, (credentials:ICredentials) => { //check on notify

                    return this.authenticateCredentials(credentials.username, credentials.password).then((user) => {
                        //credentials were successful; resolve the promises
                        deferredCredentials.resolve(user);
                        loginSuccess.resolve(user);
                    }, (err) => { //pass notification to loginSuccess
                        if (!!this.userLoggedInPromise) { //deregister the userLoggedInPromise
                            this.userLoggedInPromise = null;
                        }
                        loginSuccess.notify(err);
                    });
                })
            ;

            this.userLoggedInPromise = this.loginPromptFactory(deferredCredentials, loginSuccess.promise, this.user)
                .then(
                    () => loginSuccess.promise, //when the user has completed the login, chain on the login success promise
                    (err) => {
                        deferredCredentials.reject(); //if the user aborted login, reject the credentials promise
                        loginSuccess.reject();
                        return this.$q.reject(err); //and reject the login promise
                    }
                )
            ;

        }

        return this.userLoggedInPromise
            .then(() => {
                return this.getUser();
            })
            .finally(() => {

                if (!!this.userLoggedInPromise) { //deregister the userLoggedInPromise
                    this.userLoggedInPromise = null;
                }

            })
            ;

    }

    /**
     * Handle the login event
     * @param user
     */
    private handleLogin(user:IUser):void {

        _.invokeMap(this.loginListeners, _.call, null, user);

    }

    /**
     * Find the user object within the path
     * @param tokenData
     * @returns {ng.IPromise<IUser>}
     */
    private getUserFromTokenData(tokenData:IJwtToken):ng.IPromise<IUser> {

        return this.userFactory(tokenData.data.sub, tokenData.data)
            .then((user:IUser) => {
                this.user = user;
                return user;
            });
    }

    /**
     * Save the token
     * @param rawToken
     * @param tokenData
     */
    private saveTokenToStorage(rawToken:string, tokenData:IJwtToken):void {

        this.$window.localStorage.setItem(this.config.storageKeyName, rawToken);

        if (this.config.cookie.enabled) {
            this.saveCookie(rawToken, tokenData);
        }

    }

    /**
     * Save to cookie
     * @param rawToken
     * @param tokenData
     */
    private saveCookie(rawToken, tokenData):void {

        let cookieKey = this.config.cookie.name,
            expires = new Date(tokenData.data.exp * 1000); //set the cookie expiry to the same as the jwt

        if (this.config.cookie.topLevelDomain) {

            let hostnameParts = this.$location.host().split('.');
            let segmentCount = 1;
            let testHostname = '';
            do {
                testHostname = _.takeRight(hostnameParts, segmentCount).join('.');

                segmentCount++;
                this.$cookies.put(cookieKey, rawToken, {
                    domain: testHostname,
                    expires: expires,
                });

                if (this.$cookies.get(cookieKey)) { //saving the cookie worked, it must be the top level domain
                    return; //so exit here
                }

            } while (segmentCount < hostnameParts.length + 1); //try all the segment combinations, exit when all attempted

            throw new NgJwtAuthException("Could not set cookie for domain " + testHostname);

        } else { //use the default domain

            this.$cookies.put(cookieKey, rawToken, {
                expires: expires,
            });

        }
    }

    /**
     * Set the authentication token for all new requests
     * @param rawToken
     */
    private setJWTHeader(rawToken:String):void {

        this.$http.defaults.headers.common.Authorization = 'Bearer ' + rawToken;
    }

    /**
     * Remove the default http authorization header
     */
    private unsetJWTHeader():void {
        delete this.$http.defaults.headers.common.Authorization;
    }

    /**
     * Handle a request that was rejected due to unauthorised response
     * 1. Require authentication
     * 2. Retry the rejected $http request
     *
     * @param rejection
     */
    public handleInterceptedUnauthorisedResponse(rejection:ng.IHttpPromiseCallbackArg<any>):ng.IPromise<ng.IHttpPromise<any>> {

        return this.requireCredentialsAndAuthenticate()
            .then(() => {
                //update with the new header
                rejection.config.headers['Authorization'] = this.getBearerHeader();

                return this.$http(rejection.config);
            });
    }

    /**
     * Register the login prompt factory
     * @param loginPromptFactory
     * @returns {NgJwtAuthService}
     */
    public registerLoginPromptFactory(loginPromptFactory:ILoginPromptFactory):NgJwtAuthService {

        if (_.isFunction(this.loginPromptFactory)) {
            throw new NgJwtAuthException("You cannot redeclare the login prompt factory");
        }

        this.loginPromptFactory = loginPromptFactory;

        return this;
    }

    /**
     * Register the user factory for extracting a user from data
     * @param userFactory
     * @returns {NgJwtAuthService}
     */
    public registerUserFactory(userFactory:IUserFactory):NgJwtAuthService {

        this.userFactory = userFactory;

        return this;
    }

    /**
     * Clear the token and service properties
     */
    public logout():void {
        this.clearJWTToken();
        this.loggedIn = false;

        //call all logout listeners with user that is logged out
        _.invokeMap(this.logoutListeners, _.call, null, this.user);
        this.user = null;

        if (!!this.userLoggedInPromise) { //deregister the userLoggedInPromise
            this.userLoggedInPromise = null;
        }
    }

    /**
     * Register a login listener function
     * @param loginListener
     */
    public registerLoginListener(loginListener:IUserEventListener):void {
        this.loginListeners.push(loginListener);
    }

    /**
     * Register a logout listener function
     * @param logoutListener
     */
    public registerLogoutListener(logoutListener:IUserEventListener):void {
        this.logoutListeners.push(logoutListener);
    }

    /**
     * Get a user's token given their identifier
     * @param userIdentifier
     * @returns {ng.IPromise<IUser>}
     *
     * Note this feature should be implemented very carefully as it is a security risk as it means users
     * can log in as other users (impersonation). The responsibility is on the implementing app to strongly
     * control permissions to access this endpoint to avoid security risks
     */
    public loginAsUser(userIdentifier:string|number):ng.IPromise<IUser> {

        if (!this.loggedIn) {
            throw new NgJwtAuthException("You must be logged in to retrieve a user's token");
        }

        let authHeader = this.getBearerHeader();
        let endpoint = this.getLoginAsUserEndpoint(userIdentifier);

        return this.retrieveAndProcessToken(endpoint, authHeader);
    }

    /**
     * @returns boolean
     */
    public tokenHasExpired():boolean {

        if (!this.rawToken) {
            return false;
        }

        let expiryDate = moment(this.tokenData.data.exp * 1000);

        return expiryDate < moment();
    }

}
