"use strict";
require("angular");
var ngJwtAuthServiceProvider_1 = require("./ngJwtAuthServiceProvider");
var ngJwtAuthInterceptor_1 = require("./ngJwtAuthInterceptor");
angular.module('ngJwtAuth', ['ab-base64', 'ngCookies'])
    .provider('ngJwtAuthService', ngJwtAuthServiceProvider_1.NgJwtAuthServiceProvider)
    .service('ngJwtAuthInterceptor', ngJwtAuthInterceptor_1.NgJwtAuthInterceptor)
    .config(['$httpProvider', '$injector', function ($httpProvider) {
        $httpProvider.interceptors.push('ngJwtAuthInterceptor');
    }]);
//# sourceMappingURL=index.js.map