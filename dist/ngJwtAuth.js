/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthService = (function () {
        function NgJwtAuthService(_config, _$http) {
            this.config = _config;
            this.$http = _$http;
        }
        NgJwtAuthService.prototype.getLoginEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.login;
        };
        NgJwtAuthService.prototype.getTokenExchangeEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.tokenExchange;
        };
        NgJwtAuthService.prototype.getRefreshEndpoint = function () {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.refresh;
        };
        NgJwtAuthService.getAuthHeader = function (username, password) {
            return 'Basic ' + btoa(username + ':' + password); //note btoa is NOT supported <= IE9
        };
        NgJwtAuthService.prototype.isLoginMethod = function (url, subString) {
            return true;
        };
        NgJwtAuthService.prototype.getUser = function () {
            return {};
        };
        NgJwtAuthService.prototype.getPromisedUser = function () {
            return this.$http.get('/');
        };
        NgJwtAuthService.prototype.processNewToken = function (rawToken) {
            return true;
        };
        NgJwtAuthService.prototype.clearToken = function () {
            return true;
        };
        NgJwtAuthService.prototype.getToken = function (username, password) {
            var _this = this;
            var authHeader = NgJwtAuthService.getAuthHeader(username, password);
            var requestConfig = {
                method: 'GET',
                url: this.getLoginEndpoint(),
                headers: {
                    Authorization: authHeader
                },
                responseType: 'json'
            };
            return this.$http(requestConfig).then(function (result) {
                return _.get(result.data, _this.config.tokenLocation);
            });
        };
        NgJwtAuthService.prototype.exchangeToken = function (token) {
            return this.$http.get('/');
        };
        NgJwtAuthService.prototype.requireLogin = function () {
            return this.$http.get('/');
        };
        NgJwtAuthService.prototype.getRemoteData = function (url) {
            var requestConfig = {
                method: 'GET',
                url: url,
                responseType: 'json'
            };
            return this.$http(requestConfig);
        };
        return NgJwtAuthService;
    })();
    NgJwtAuth.NgJwtAuthService = NgJwtAuthService;
})(NgJwtAuth || (NgJwtAuth = {}));
/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
/// <reference path="./ngJwtAuthService.ts" />
var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthServiceProvider = (function () {
        function NgJwtAuthServiceProvider() {
            //public $get(): INgJwtAuthService {
            //
            //    return new NgJwtAuthService();
            //}
            this.$get = ["$http", function NgJwtAuthServiceFactory($http) {
                    return new NgJwtAuth.NgJwtAuthService(this.config, $http);
                }];
            //initialise service config
            this.config = {
                tokenLocation: 'token',
                tokenUser: '#user',
                loginController: 'app.public.login',
                apiEndpoints: {
                    base: '/api/auth',
                    login: '/login',
                    tokenExchange: '/token',
                    refresh: '/refresh'
                }
            };
        }
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        NgJwtAuthServiceProvider.prototype.setApiEndpoints = function (config) {
            this.config.apiEndpoints = _.defaults(config, this.config.apiEndpoints);
            return this;
        };
        return NgJwtAuthServiceProvider;
    })();
    NgJwtAuth.NgJwtAuthServiceProvider = NgJwtAuthServiceProvider;
    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider);
})(NgJwtAuth || (NgJwtAuth = {}));
//# sourceMappingURL=ngJwtAuth.js.map