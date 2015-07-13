var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthInterceptor = (function () {
        function NgJwtAuthInterceptor(_$q, _$injector) {
            var _this = this;
            this.getNgJwtAuthService = function () {
                if (_this.ngJwtAuthService == null) {
                    _this.ngJwtAuthService = _this.$injector.get('ngJwtAuthService');
                }
                return _this.ngJwtAuthService;
            };
            this.responseError = function (rejection) {
                var ngJwtAuthService = _this.getNgJwtAuthService();
                //if the response is on a login method, reject immediately
                if (ngJwtAuthService.isLoginMethod(rejection.config.url)) {
                    return _this.$q.reject(rejection);
                }
                if (401 === rejection.status) {
                    return ngJwtAuthService.handleInterceptedUnauthorisedResponse(rejection);
                }
                return _this.$q.reject(rejection);
            };
            this.$q = _$q;
            this.$injector = _$injector;
        }
        /**
         * Construct the service with dependencies injected
         * @param _$q
         * @param _$injector
         */
        NgJwtAuthInterceptor.$inject = ['$q', '$injector'];
        return NgJwtAuthInterceptor;
    })();
    NgJwtAuth.NgJwtAuthInterceptor = NgJwtAuthInterceptor;
})(NgJwtAuth || (NgJwtAuth = {}));
/// <reference path="../typings/tsd.d.ts" />
var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthService = (function () {
        /**
         * Construct the service with dependencies injected
         * @param _config
         * @param _$http
         * @param _$q
         * @param _$window
         * @param _$interval
         */
        function NgJwtAuthService(_config, _$http, _$q, _$window, _$interval) {
            var _this = this;
            //public properties
            this.loggedIn = false;
            /**
             * Handle token refresh timer
             */
            this.tickRefreshTime = function () {
                if (_this.tokenNeedsToRefreshNow()) {
                    _this.refreshToken();
                }
            };
            this.config = _config;
            this.$http = _$http;
            this.$q = _$q;
            this.$window = _$window;
            this.$interval = _$interval;
        }
        /**
         * Service needs an init function so runtime configuration can occur before
         * bootstrapping the service. This allows the user supplied CredentialPromiseFactory
         * to be registered
         */
        NgJwtAuthService.prototype.init = function () {
            //attempt to load the token from storage
            this.loadTokenFromStorage();
            this.refreshTimerPromise = this.$interval(this.tickRefreshTime, this.config.checkExpiryEverySeconds * 1000, null, false);
        };
        /**
         * Check if the token needs to refresh now
         * @returns {boolean}
         */
        NgJwtAuthService.prototype.tokenNeedsToRefreshNow = function () {
            if (!this.rawToken) {
                return false; //cant refresh if there isn't a token
            }
            var latestRefresh = moment(this.tokenData.data.exp * 1000).subtract(this.config.refreshBeforeSeconds, 'seconds'), nextRefreshOpportunity = moment().add(this.config.checkExpiryEverySeconds);
            //needs to refresh if the the next time we could refresh is after the configured refresh before date
            return (latestRefresh <= nextRefreshOpportunity);
        };
        /**
         * Get the endpoint for login
         * @returns {string}
         */
        NgJwtAuthService.prototype.getLoginEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.login;
        };
        /**
         * Get the endpoint for exchanging a token
         * @returns {string}
         */
        NgJwtAuthService.prototype.getTokenExchangeEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.tokenExchange;
        };
        /**
         * Get the endpoint for refreshing a token
         * @returns {string}
         */
        NgJwtAuthService.prototype.getRefreshEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.refresh;
        };
        /**
         * Build a authentication basic header string
         * @param username
         * @param password
         * @returns {string}
         */
        NgJwtAuthService.getAuthHeader = function (username, password) {
            return 'Basic ' + btoa(username + ':' + password); //note btoa is NOT supported <= IE9
        };
        /**
         * Build a token header string
         * @returns {string}
         */
        NgJwtAuthService.getTokenHeader = function (token) {
            return 'Token ' + token;
        };
        /**
         * Build a refresh header string
         * @returns {string}
         */
        NgJwtAuthService.prototype.getRefreshHeader = function () {
            if (!this.rawToken) {
                throw new NgJwtAuth.NgJwtAuthException("Token is not set, it cannot be refreshed");
            }
            return 'Bearer ' + this.rawToken;
        };
        /**
         * Retrieve the token from the remote API
         * @param endpoint
         * @param authHeader
         * @returns {IPromise<TResult>}
         */
        NgJwtAuthService.prototype.retrieveAndProcessToken = function (endpoint, authHeader) {
            var _this = this;
            var requestConfig = {
                method: 'GET',
                url: endpoint,
                headers: {
                    Authorization: authHeader
                },
                responseType: 'json'
            };
            return this.$http(requestConfig).then(function (result) {
                return _.get(result.data, _this.config.tokenLocation);
            })
                .then(function (token) {
                try {
                    return _this.processNewToken(token);
                }
                catch (error) {
                    return _this.$q.reject(error);
                }
            })
                .catch(function (result) {
                if (result.status === 401) {
                    //throw new NgJwtAuthException("Login attempt received unauthorised response");
                    return _this.$q.reject(new NgJwtAuth.NgJwtAuthException("Login attempt received unauthorised response"));
                }
                //throw new NgJwtAuthException("The API reported an error");
                return _this.$q.reject(new NgJwtAuth.NgJwtAuthException("The API reported an error"));
            });
        };
        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        NgJwtAuthService.readToken = function (rawToken) {
            if ((rawToken.match(/\./g) || []).length !== 2) {
                throw new NgJwtAuth.NgJwtAuthException("Raw token is has incorrect format. Format must be of form \"[header].[data].[signature]\"");
            }
            var pieces = rawToken.split('.');
            var jwt = {
                header: angular.fromJson(atob(pieces[0])),
                data: angular.fromJson(atob(pieces[1])),
                signature: pieces[2],
            };
            return jwt;
        };
        /**
         * Read and save the raw token to storage, kick off timer to attempt refresh
         * @param rawToken
         * @returns {IUser}
         */
        NgJwtAuthService.prototype.processNewToken = function (rawToken) {
            this.rawToken = rawToken;
            this.tokenData = NgJwtAuthService.readToken(rawToken);
            var expiryDate = moment(this.tokenData.data.exp * 1000);
            if (expiryDate < moment()) {
                throw new NgJwtAuth.NgJwtAuthTokenExpiredException("Token has expired");
            }
            this.saveTokenToStorage(rawToken);
            this.setJWTHeader(rawToken);
            this.loggedIn = true;
            this.user = this.getUserFromTokenData(this.tokenData);
            return this.user;
        };
        NgJwtAuthService.prototype.loadTokenFromStorage = function () {
            var rawToken = this.$window.localStorage.getItem(this.config.storageKeyName);
            if (!rawToken) {
                return false;
            }
            try {
                this.processNewToken(rawToken);
                return true;
            }
            catch (e) {
                if (e instanceof NgJwtAuth.NgJwtAuthTokenExpiredException) {
                    this.requireCredentialsAndAuthenticate();
                }
            }
            return false;
        };
        /**
         * Check if the endpoint is a login method (used for skipping the authentication error interceptor)
         * @param url
         * @returns {boolean}
         */
        NgJwtAuthService.prototype.isLoginMethod = function (url) {
            var loginMethods = [
                this.getLoginEndpoint(),
                this.getTokenExchangeEndpoint(),
            ];
            return _.contains(loginMethods, url);
        };
        NgJwtAuthService.prototype.getUser = function () {
            return this.user;
        };
        /**
         *
         * @returns {IHttpPromise<T>}
         */
        NgJwtAuthService.prototype.getPromisedUser = function () {
            if (this.loggedIn) {
                return this.$q.when(this.user);
            }
            else {
                return this.requireCredentialsAndAuthenticate()
                    .then(function (authenticatedUser) {
                    return authenticatedUser;
                });
            }
        };
        /**
         * Clear the token
         */
        NgJwtAuthService.prototype.clearJWTToken = function () {
            this.rawToken = null;
            this.$window.localStorage.removeItem(this.config.storageKeyName);
            this.unsetJWTHeader();
        };
        /**
         * Attempt to log in with username and password
         * @param username
         * @param password
         * @returns {IPromise<boolean>}
         */
        NgJwtAuthService.prototype.authenticateCredentials = function (username, password) {
            var authHeader = NgJwtAuthService.getAuthHeader(username, password);
            var endpoint = this.getLoginEndpoint();
            return this.retrieveAndProcessToken(endpoint, authHeader);
        };
        /**
         * Exchange an arbitrary token with a jwt token
         * @param token
         * @returns {ng.IPromise<any>}
         */
        NgJwtAuthService.prototype.exchangeToken = function (token) {
            var authHeader = NgJwtAuthService.getTokenHeader(token);
            var endpoint = this.getTokenExchangeEndpoint();
            return this.retrieveAndProcessToken(endpoint, authHeader);
        };
        /**
         * Refresh an existing token
         * @returns {ng.IPromise<any>}
         */
        NgJwtAuthService.prototype.refreshToken = function () {
            var authHeader = this.getRefreshHeader();
            var endpoint = this.getRefreshEndpoint();
            return this.retrieveAndProcessToken(endpoint, authHeader);
        };
        /**
         * Require that the user logs in again for a request
         * 1. Check if there is already credentials promised
         * 2. If not, execute the credential promise factory
         * 3. Wait until the credentials are resolved
         * 4. Then try to authenticateCredentials
         * @returns {IPromise<TResult>}
         */
        NgJwtAuthService.prototype.requireCredentialsAndAuthenticate = function () {
            var _this = this;
            if (!_.isFunction(this.credentialPromiseFactory)) {
                throw new NgJwtAuth.NgJwtAuthException("You must set a credentialPromiseFactory with `ngJwtAuthService.registerCredentialPromiseFactory()` so the user can be prompted for their credentials");
            }
            if (!this.currentCredentialPromise) {
                this.currentCredentialPromise = this.credentialPromiseFactory(this.user);
            }
            return this.currentCredentialPromise.then(function (credentials) {
                if (_this.currentCredentialPromise) {
                    _this.currentCredentialPromise = null;
                }
                return _this.authenticateCredentials(credentials.username, credentials.password);
            });
        };
        /**
         * Find the user object within the path
         * @param tokenData
         * @returns {T}
         */
        NgJwtAuthService.prototype.getUserFromTokenData = function (tokenData) {
            return _.get(tokenData.data, this.config.tokenUser);
        };
        /**
         * Save the token
         * @param rawToken
         */
        NgJwtAuthService.prototype.saveTokenToStorage = function (rawToken) {
            this.$window.localStorage.setItem(this.config.storageKeyName, rawToken);
        };
        /**
         * Set the authentication token for all new requests
         * @param rawToken
         */
        NgJwtAuthService.prototype.setJWTHeader = function (rawToken) {
            this.$http.defaults.headers.common.Authorization = 'Bearer ' + rawToken;
        };
        /**
         * Remove the default http authorization header
         */
        NgJwtAuthService.prototype.unsetJWTHeader = function () {
            delete this.$http.defaults.headers.common.Authorization;
        };
        /**
         * Handle a request that was rejected due to unauthorised response
         * 1. Require authentication
         * 2. Retry the rejected $http request
         *
         * @param rejection
         */
        NgJwtAuthService.prototype.handleInterceptedUnauthorisedResponse = function (rejection) {
            var _this = this;
            this.requireCredentialsAndAuthenticate()
                .then(function (user) {
                return _this.$http(rejection.config);
            });
        };
        /**
         * Register the user provided credential promise factory
         * @param promiseFactory
         */
        NgJwtAuthService.prototype.registerCredentialPromiseFactory = function (promiseFactory) {
            if (_.isFunction(this.credentialPromiseFactory)) {
                throw new NgJwtAuth.NgJwtAuthException("You cannot redeclare the credential promise factory");
            }
            this.credentialPromiseFactory = promiseFactory;
            return this;
        };
        /**
         * Clear the token and service properties
         */
        NgJwtAuthService.prototype.logout = function () {
            this.clearJWTToken();
            this.loggedIn = false;
            this.user = null;
        };
        return NgJwtAuthService;
    })();
    NgJwtAuth.NgJwtAuthService = NgJwtAuthService;
})(NgJwtAuth || (NgJwtAuth = {}));
var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthException = (function (_super) {
        __extends(NgJwtAuthException, _super);
        function NgJwtAuthException(message) {
            _super.call(this, message);
            this.message = message;
            this.name = 'NgJwtAuthException';
            this.message = message;
            this.stack = (new Error()).stack;
        }
        NgJwtAuthException.prototype.toString = function () {
            return this.name + ': ' + this.message;
        };
        return NgJwtAuthException;
    })(Error);
    NgJwtAuth.NgJwtAuthException = NgJwtAuthException;
    var NgJwtAuthTokenExpiredException = (function (_super) {
        __extends(NgJwtAuthTokenExpiredException, _super);
        function NgJwtAuthTokenExpiredException() {
            _super.apply(this, arguments);
        }
        return NgJwtAuthTokenExpiredException;
    })(NgJwtAuthException);
    NgJwtAuth.NgJwtAuthTokenExpiredException = NgJwtAuthTokenExpiredException;
    var NgJwtAuthServiceProvider = (function () {
        /**
         * Initialise the service provider
         */
        function NgJwtAuthServiceProvider() {
            this.$get = ['$http', '$q', '$window', '$interval', function NgJwtAuthServiceFactory($http, $q, $window, $interval) {
                    return new NgJwtAuth.NgJwtAuthService(this.config, $http, $q, $window, $interval);
                }];
            //initialise service config
            this.config = {
                tokenLocation: 'token',
                tokenUser: '#user',
                apiEndpoints: {
                    base: '/api/auth',
                    login: '/login',
                    tokenExchange: '/token',
                    refresh: '/refresh',
                },
                storageKeyName: 'NgJwtAuthToken',
                refreshBeforeSeconds: 60 * 2,
                checkExpiryEverySeconds: 60,
            };
        }
        /**
         * Set the configuration
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        NgJwtAuthServiceProvider.prototype.configure = function (config) {
            this.config = _.defaults(config, this.config.apiEndpoints);
            return this;
        };
        return NgJwtAuthServiceProvider;
    })();
    NgJwtAuth.NgJwtAuthServiceProvider = NgJwtAuthServiceProvider;
    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
        .service('ngJwtAuthInterceptor', NgJwtAuth.NgJwtAuthInterceptor)
        .config(['$httpProvider', '$injector', function ($httpProvider) {
            $httpProvider.interceptors.push('ngJwtAuthInterceptor');
        }]);
})(NgJwtAuth || (NgJwtAuth = {}));

//# sourceMappingURL=ngJwtAuth.js.map