/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
var NgJwtAuth;
(function (NgJwtAuth) {
    var NgJwtAuthServiceProvider = (function () {
        function NgJwtAuthServiceProvider() {
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
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        NgJwtAuthServiceProvider.prototype.setApiEndpoints = function (config) {
            this.apiEndpoints = _.defaults(config, this.apiEndpoints);
            return this;
        };
        NgJwtAuthServiceProvider.prototype.$get = function () {
            return new NgJwtAuthService(null);
        };
        return NgJwtAuthServiceProvider;
    })();
    NgJwtAuth.NgJwtAuthServiceProvider = NgJwtAuthServiceProvider;
    var NgJwtAuthService = (function () {
        function NgJwtAuthService($http) {
            _.assign(this, $http); //bind injected dependencies
        }
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
        NgJwtAuthService.prototype.authenticate = function (username, password) {
            return this.$http.get('/');
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
        NgJwtAuthService.$inject = ['$http'];
        return NgJwtAuthService;
    })();
    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider);
})(NgJwtAuth || (NgJwtAuth = {}));
//# sourceMappingURL=ngJwtAuth.js.map