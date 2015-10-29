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
            this.response = function (response) {
                var updateHeader = response.headers('Authorization-Update');
                if (updateHeader) {
                    var newToken = updateHeader.replace('Bearer ', '');
                    var ngJwtAuthService = _this.getNgJwtAuthService();
                    if (!ngJwtAuthService.validateToken(newToken)) {
                        return response; //if it is not a valid JWT, just return the response as it might be some other kind of token that is being updated.
                    }
                    ngJwtAuthService.processNewToken(newToken);
                }
                return response;
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
         * @param config
         * @param $http
         * @param $q
         * @param $window
         * @param $interval
         * @param base64Service
         * @param $cookies
         * @param $location
         */
        function NgJwtAuthService(config, $http, $q, $window, $interval, base64Service, $cookies, $location) {
            var _this = this;
            this.config = config;
            this.$http = $http;
            this.$q = $q;
            this.$window = $window;
            this.$interval = $interval;
            this.base64Service = base64Service;
            this.$cookies = $cookies;
            this.$location = $location;
            this.loginListeners = [];
            this.loggedIn = false;
            /**
             * Handle token refresh timer
             */
            this.tickRefreshTime = function () {
                if (!_this.userLoggedInPromise && _this.tokenNeedsToRefreshNow()) {
                    _this.refreshToken();
                }
            };
            this.userFactory = this.defaultUserFactory;
        }
        /**
         * Get the current configuration
         * @returns {INgJwtAuthServiceConfig}
         */
        NgJwtAuthService.prototype.getConfig = function () {
            return this.config;
        };
        /**
         * A default implementation of the user factory if the client does not provide one
         */
        NgJwtAuthService.prototype.defaultUserFactory = function (subClaim, tokenData) {
            return this.$q.when(_.get(tokenData, this.config.tokenUser));
        };
        /**
         * Service needs an init function so runtime configuration can occur before
         * bootstrapping the service. This allows the user supplied LoginPromptFactory
         * to be registered
         */
        NgJwtAuthService.prototype.init = function () {
            var _this = this;
            //attempt to load the token from storage
            return this.loadTokenFromStorage()
                .then(function () {
                _this.startRefreshTimer();
                return true;
            });
        };
        /**
         * Register the refresh timer
         */
        NgJwtAuthService.prototype.startRefreshTimer = function () {
            //if the timer is already set, clear it so the timing is reset
            if (!!this.refreshTimerPromise) {
                this.cancelRefreshTimer();
            }
            this.refreshTimerPromise = this.$interval(this.tickRefreshTime, this.config.checkExpiryEverySeconds * 1000, null, false);
        };
        /**
         * Cancel the refresh timer
         */
        NgJwtAuthService.prototype.cancelRefreshTimer = function () {
            this.$interval.cancel(this.refreshTimerPromise);
            this.refreshTimerPromise = null;
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
         * Get the endpoint for getting a user's token (impersonation)
         * @returns {string}
         */
        NgJwtAuthService.prototype.getLoginAsUserEndpoint = function (userIdentifier) {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.loginAsUser + '/' + userIdentifier;
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
         * Get the standard header for a jwt token request
         * @returns {string}
         */
        NgJwtAuthService.prototype.getBearerHeader = function () {
            if (!this.rawToken) {
                throw new NgJwtAuth.NgJwtAuthException("Token is not set");
            }
            return 'Bearer ' + this.rawToken;
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
                if (result && result.data) {
                    var token = _.get(result.data, _this.config.tokenLocation);
                    if (_.isString(token)) {
                        return token;
                    }
                }
                return _this.$q.reject(new NgJwtAuth.NgJwtAuthException("Token could not be found in response body"));
            })
                .then(function (token) {
                try {
                    return _this.processNewToken(token);
                }
                catch (error) {
                    return _this.$q.reject(error);
                }
            })
                .catch(function (e) {
                if (_.isError(e) || e instanceof _this.$window.Error) {
                    return _this.$q.reject(new NgJwtAuth.NgJwtAuthException(e.message));
                }
                if (e.status === 401) {
                    return _this.$q.reject(new NgJwtAuth.NgJwtAuthCredentialsFailedException("Login attempt received unauthorised response"));
                }
                return _this.$q.reject(new NgJwtAuth.NgJwtAuthException("The API reported an error - " + e.status + " " + e.statusText));
            });
        };
        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        NgJwtAuthService.prototype.readToken = function (rawToken) {
            if ((rawToken.match(/\./g) || []).length !== 2) {
                throw new NgJwtAuth.NgJwtAuthException("Raw token is has incorrect format. Format must be of form \"[header].[data].[signature]\"");
            }
            var pieces = rawToken.split('.');
            var jwt = {
                header: angular.fromJson(this.base64Service.urldecode(pieces[0])),
                data: angular.fromJson(this.base64Service.urldecode(pieces[1])),
                signature: pieces[2],
            };
            return jwt;
        };
        /**
         * Validate JWT Token
         * @param rawToken
         * @returns {any}
         */
        NgJwtAuthService.prototype.validateToken = function (rawToken) {
            try {
                var tokenData = this.readToken(rawToken);
                return _.isObject(tokenData);
            }
            catch (e) {
                return false;
            }
        };
        /**
         * Prompt user for their login credentials, and attempt to login
         * @returns {ng.IPromise<IUser>}
         */
        NgJwtAuthService.prototype.promptLogin = function () {
            return this.requireCredentialsAndAuthenticate();
        };
        /**
         * Read and save the raw token to storage, kick off timer to attempt refresh
         * @param rawToken
         * @returns {IUser}
         */
        NgJwtAuthService.prototype.processNewToken = function (rawToken) {
            var _this = this;
            this.rawToken = rawToken;
            this.tokenData = this.readToken(rawToken);
            var expiryDate = moment(this.tokenData.data.exp * 1000);
            if (expiryDate < moment()) {
                throw new NgJwtAuth.NgJwtAuthTokenExpiredException("Token has expired");
            }
            this.saveTokenToStorage(rawToken, this.tokenData);
            this.setJWTHeader(rawToken);
            this.loggedIn = true;
            this.startRefreshTimer();
            var userFromToken = this.getUserFromTokenData(this.tokenData);
            userFromToken.then(function (user) { return _this.handleLogin(user); });
            return userFromToken;
        };
        NgJwtAuthService.prototype.loadTokenFromStorage = function () {
            var rawToken = this.$window.localStorage.getItem(this.config.storageKeyName);
            if (!rawToken) {
                return this.$q.when("No token in storage");
            }
            try {
                return this.processNewToken(rawToken);
            }
            catch (e) {
                if (e instanceof NgJwtAuth.NgJwtAuthTokenExpiredException) {
                    return this.requireCredentialsAndAuthenticate();
                }
                return this.$q.reject(e);
            }
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
                return this.requireCredentialsAndAuthenticate();
            }
        };
        /**
         * Clear the token
         */
        NgJwtAuthService.prototype.clearJWTToken = function () {
            this.rawToken = null;
            this.$window.localStorage.removeItem(this.config.storageKeyName);
            if (this.config.cookie.enabled) {
                this.$cookies.remove(this.config.cookie.name);
            }
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
            var _this = this;
            var authHeader = this.getRefreshHeader();
            var endpoint = this.getRefreshEndpoint();
            return this.retrieveAndProcessToken(endpoint, authHeader)
                .catch(function (err) {
                _this.cancelRefreshTimer(); //if token refreshing fails, stop the refresh timer
                return _this.$q.reject(err);
            });
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
            if (!_.isFunction(this.loginPromptFactory)) {
                throw new NgJwtAuth.NgJwtAuthException("You must set a loginPromptFactory with `ngJwtAuthService.registerLoginPromptFactory()` so the user can be prompted for their credentials");
            }
            if (!this.userLoggedInPromise) {
                var deferredCredentials = this.$q.defer();
                var loginSuccess = this.$q.defer();
                deferredCredentials.promise
                    .then(null, null, function (credentials) {
                    return _this.authenticateCredentials(credentials.username, credentials.password).then(function (user) {
                        //credentials were successful; resolve the promises
                        deferredCredentials.resolve(user);
                        loginSuccess.resolve(user);
                    }, function (err) {
                        loginSuccess.notify(err);
                    });
                });
                this.userLoggedInPromise = this.loginPromptFactory(deferredCredentials, loginSuccess.promise, this.user)
                    .then(function () { return loginSuccess.promise; }, function (err) {
                    deferredCredentials.reject(); //if the user aborted login, reject the credentials promise
                    loginSuccess.reject();
                    return _this.$q.reject(err); //and reject the login promise
                });
            }
            return this.userLoggedInPromise
                .then(function () {
                return _this.getUser();
            })
                .finally(function () {
                if (!!_this.userLoggedInPromise) {
                    _this.userLoggedInPromise = null;
                }
            });
        };
        /**
         * Handle the login event
         * @param user
         */
        NgJwtAuthService.prototype.handleLogin = function (user) {
            _.each(this.loginListeners, function (listener) {
                listener(user);
            });
        };
        /**
         * Find the user object within the path
         * @param tokenData
         * @returns {T}
         */
        NgJwtAuthService.prototype.getUserFromTokenData = function (tokenData) {
            var _this = this;
            return this.userFactory(tokenData.data.sub, tokenData.data)
                .then(function (user) {
                _this.user = user;
                return user;
            });
        };
        /**
         * Save the token
         * @param rawToken
         * @param tokenData
         */
        NgJwtAuthService.prototype.saveTokenToStorage = function (rawToken, tokenData) {
            this.$window.localStorage.setItem(this.config.storageKeyName, rawToken);
            if (this.config.cookie.enabled) {
                this.saveCookie(rawToken, tokenData);
            }
        };
        /**
         * Save to cookie
         * @param rawToken
         * @param tokenData
         */
        NgJwtAuthService.prototype.saveCookie = function (rawToken, tokenData) {
            var cookieKey = this.config.cookie.name, expires = new Date(tokenData.data.exp * 1000); //set the cookie expiry to the same as the jwt
            if (this.config.cookie.topLevelDomain) {
                var hostnameParts = this.$location.host().split('.');
                var segmentCount = 1;
                var testHostname = '';
                do {
                    //definitely typed does not have a definition for lodash's _.takeRight
                    testHostname = _.takeRight(hostnameParts, segmentCount).join('.');
                    segmentCount++;
                    this.$cookies.put(cookieKey, rawToken, {
                        domain: testHostname,
                        expiry: expires,
                    });
                    if (this.$cookies.get(cookieKey)) {
                        return; //so exit here
                    }
                } while (segmentCount < hostnameParts.length + 1); //try all the segment combinations, exit when all attempted
                throw new NgJwtAuth.NgJwtAuthException("Could not set cookie for domain " + testHostname);
            }
            else {
                this.$cookies.put(cookieKey, rawToken, {
                    expires: expires,
                });
            }
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
            return this.requireCredentialsAndAuthenticate()
                .then(function () {
                //update with the new header
                rejection.config.headers.Authorization = _this.getBearerHeader();
                return _this.$http(rejection.config);
            });
        };
        /**
         * Register the login prompt factory
         * @param loginPromptFactory
         * @returns {NgJwtAuth.NgJwtAuthService}
         */
        NgJwtAuthService.prototype.registerLoginPromptFactory = function (loginPromptFactory) {
            if (_.isFunction(this.loginPromptFactory)) {
                throw new NgJwtAuth.NgJwtAuthException("You cannot redeclare the login prompt factory");
            }
            this.loginPromptFactory = loginPromptFactory;
            return this;
        };
        /**
         * Register the user factory for extracting a user from data
         * @param userFactory
         * @returns {NgJwtAuth.NgJwtAuthService}
         */
        NgJwtAuthService.prototype.registerUserFactory = function (userFactory) {
            this.userFactory = userFactory;
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
        /**
         * Register a login listener function
         * @param loginListener
         */
        NgJwtAuthService.prototype.registerLoginListener = function (loginListener) {
            this.loginListeners.push(loginListener);
        };
        /**
         * Get a user's token given their identifier
         * @param userIdentifier
         * @returns {ng.IPromise<IUser>}
         *
         * Note this feature should be implemented very carefully as it is a security risk as it means users
         * can log in as other users (impersonation). The responsibility is on the implementing app to strongly
         * control permissions to access this endpoint to avoid security risks
         */
        NgJwtAuthService.prototype.loginAsUser = function (userIdentifier) {
            if (!this.loggedIn) {
                throw new NgJwtAuth.NgJwtAuthException("You must be logged in to retrieve a user's token");
            }
            var authHeader = this.getBearerHeader();
            var endpoint = this.getLoginAsUserEndpoint(userIdentifier);
            return this.retrieveAndProcessToken(endpoint, authHeader);
        };
        return NgJwtAuthService;
    })();
    NgJwtAuth.NgJwtAuthService = NgJwtAuthService;
})(NgJwtAuth || (NgJwtAuth = {}));
var __extends = (this && this.__extends) || function (d, b) {
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
    var NgJwtAuthCredentialsFailedException = (function (_super) {
        __extends(NgJwtAuthCredentialsFailedException, _super);
        function NgJwtAuthCredentialsFailedException() {
            _super.apply(this, arguments);
        }
        return NgJwtAuthCredentialsFailedException;
    })(NgJwtAuthException);
    NgJwtAuth.NgJwtAuthCredentialsFailedException = NgJwtAuthCredentialsFailedException;
    var NgJwtAuthServiceProvider = (function () {
        /**
         * Initialise the service provider
         */
        function NgJwtAuthServiceProvider() {
            this.$get = ['$http', '$q', '$window', '$interval', 'base64', '$cookies', '$location', function NgJwtAuthServiceFactory($http, $q, $window, $interval, base64, $cookies, $location) {
                    return new NgJwtAuth.NgJwtAuthService(this.config, $http, $q, $window, $interval, base64, $cookies, $location);
                }];
            //initialise service config
            this.config = {
                tokenLocation: 'token',
                tokenUser: '#user',
                apiEndpoints: {
                    base: '/api/auth',
                    login: '/login',
                    tokenExchange: '/token',
                    loginAsUser: '/user',
                    refresh: '/refresh',
                },
                storageKeyName: 'NgJwtAuthToken',
                refreshBeforeSeconds: 60 * 2,
                checkExpiryEverySeconds: 60,
                cookie: {
                    enabled: false,
                    name: 'ngJwtAuthToken',
                    topLevelDomain: false,
                }
            };
        }
        /**
         * Set the configuration
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        NgJwtAuthServiceProvider.prototype.configure = function (config) {
            var mismatchedConfig = _.difference(_.keys(config), _.keys(this.config));
            if (mismatchedConfig.length > 0) {
                throw new NgJwtAuthException("Invalid properties [" + mismatchedConfig.join(',') + "] passed to config)");
            }
            this.config = _.defaultsDeep(config, this.config);
            return this;
        };
        return NgJwtAuthServiceProvider;
    })();
    NgJwtAuth.NgJwtAuthServiceProvider = NgJwtAuthServiceProvider;
    angular.module('ngJwtAuth', ['ab-base64', 'ngCookies'])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
        .service('ngJwtAuthInterceptor', NgJwtAuth.NgJwtAuthInterceptor)
        .config(['$httpProvider', '$injector', function ($httpProvider) {
            $httpProvider.interceptors.push('ngJwtAuthInterceptor');
        }]);
})(NgJwtAuth || (NgJwtAuth = {}));

//# sourceMappingURL=ngJwtAuth.js.map