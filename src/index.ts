import "angular";
import {NgJwtAuthServiceProvider} from "./ngJwtAuthServiceProvider";
import {NgJwtAuthInterceptor} from "./ngJwtAuthInterceptor";


angular.module('ngJwtAuth', ['ab-base64', 'ngCookies'])
    .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
    .service('ngJwtAuthInterceptor', NgJwtAuthInterceptor)
    .config(['$httpProvider', '$injector', ($httpProvider:ng.IHttpProvider) => {

        $httpProvider.interceptors.push('ngJwtAuthInterceptor');
    }])
;