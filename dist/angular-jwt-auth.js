/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
var AngularJwtAuth;
(function (AngularJwtAuth) {
    var AngularJwtAuthServiceProvider = (function () {
        function AngularJwtAuthServiceProvider($http) {
            _.assign(this, $http); //bind injected dependencies
            this.apiEndpoints = {
                base: '/api/auth',
                login: '/login',
                tokenExchange: '/token',
                refresh: '/refresh'
            };
        }
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {AngularJwtAuth.AngularJwtAuthServiceProvider}
         */
        AngularJwtAuthServiceProvider.prototype.setApiEndpoints = function (config) {
            this.apiEndpoints = _.defaults(config, this.apiEndpoints);
            return this;
        };
        AngularJwtAuthServiceProvider.prototype.getRemoteData = function (url) {
            var requestConfig = {
                method: 'GET',
                url: url,
                responseType: 'json'
            };
            return this.$http(requestConfig);
        };
        AngularJwtAuthServiceProvider.prototype.$get = function () {
            return new AngularJwtAuthService(this.$http);
        };
        AngularJwtAuthServiceProvider.$inject = ['$http'];
        return AngularJwtAuthServiceProvider;
    })();
    AngularJwtAuth.AngularJwtAuthServiceProvider = AngularJwtAuthServiceProvider;
    var AngularJwtAuthService = (function () {
        function AngularJwtAuthService($http) {
            //bind injected dependencies
            this.$http = $http;
        }
        AngularJwtAuthService.prototype.isLoginMethod = function (url, subString) {
            return true;
        };
        AngularJwtAuthService.prototype.getUser = function () {
            return {};
        };
        AngularJwtAuthService.prototype.getPromisedUser = function () {
            return this.$http.get('/');
        };
        AngularJwtAuthService.prototype.processNewToken = function (rawToken) {
            return true;
        };
        AngularJwtAuthService.prototype.clearToken = function () {
            return true;
        };
        AngularJwtAuthService.prototype.authenticate = function (username, password) {
            return this.$http.get('/');
        };
        AngularJwtAuthService.prototype.exchangeToken = function (token) {
            return this.$http.get('/');
        };
        AngularJwtAuthService.prototype.requireLogin = function () {
            return this.$http.get('/');
        };
        return AngularJwtAuthService;
    })();
    angular.module('angularJwtAuth', []).provider('angularJwtAuthService', AngularJwtAuthServiceProvider);
})(AngularJwtAuth || (AngularJwtAuth = {}));
