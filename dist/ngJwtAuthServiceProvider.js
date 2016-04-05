"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var ngJwtAuthService_1 = require("./ngJwtAuthService");
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
}(Error));
exports.NgJwtAuthException = NgJwtAuthException;
var NgJwtAuthTokenExpiredException = (function (_super) {
    __extends(NgJwtAuthTokenExpiredException, _super);
    function NgJwtAuthTokenExpiredException() {
        _super.apply(this, arguments);
    }
    return NgJwtAuthTokenExpiredException;
}(NgJwtAuthException));
exports.NgJwtAuthTokenExpiredException = NgJwtAuthTokenExpiredException;
var NgJwtAuthCredentialsFailedException = (function (_super) {
    __extends(NgJwtAuthCredentialsFailedException, _super);
    function NgJwtAuthCredentialsFailedException() {
        _super.apply(this, arguments);
    }
    return NgJwtAuthCredentialsFailedException;
}(NgJwtAuthException));
exports.NgJwtAuthCredentialsFailedException = NgJwtAuthCredentialsFailedException;
var NgJwtAuthServiceProvider = (function () {
    /**
     * Initialise the service provider
     */
    function NgJwtAuthServiceProvider() {
        this.$get = ['$http', '$q', '$window', '$interval', 'base64', '$cookies', '$location', function NgJwtAuthServiceFactory($http, $q, $window, $interval, base64, $cookies, $location) {
                return new ngJwtAuthService_1.NgJwtAuthService(this.config, $http, $q, $window, $interval, base64, $cookies, $location);
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
}());
exports.NgJwtAuthServiceProvider = NgJwtAuthServiceProvider;
//# sourceMappingURL=ngJwtAuthServiceProvider.js.map