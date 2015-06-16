/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
var AngularJwtAuth;
(function (AngularJwtAuth) {
    var AngularJwtAuthServiceProvider = (function () {
        function AngularJwtAuthServiceProvider($http) {
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
         * @returns {AngularJwtAuth.AngularJwtAuthService}
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
        };
        AngularJwtAuthServiceProvider.$inject = ['$http'];
        return AngularJwtAuthServiceProvider;
    })();
    AngularJwtAuth.AngularJwtAuthServiceProvider = AngularJwtAuthServiceProvider;
    angular.module('angularJwtAuth', []).provider('angularJwtAuthService', AngularJwtAuthServiceProvider);
})(AngularJwtAuth || (AngularJwtAuth = {}));
