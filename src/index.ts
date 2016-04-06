import "angular";
import "angular-cookies";
import "angular-utf8-base64";

import {NgJwtAuthServiceProvider} from "./provider/ngJwtAuthServiceProvider";
import {NgJwtAuthInterceptor} from "./interceptor/ngJwtAuthInterceptor";

angular.module('ngJwtAuth', ['utf8-base64', 'ngCookies'])
    .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
    .service('ngJwtAuthInterceptor', NgJwtAuthInterceptor)
    .config(['$httpProvider', '$injector', ($httpProvider:ng.IHttpProvider) => {

        $httpProvider.interceptors.push('ngJwtAuthInterceptor');
    }])
;