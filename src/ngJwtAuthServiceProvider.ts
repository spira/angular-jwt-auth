/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
/// <reference path="./ngJwtAuthService.ts" />
/// <reference path="./ngJwtAuthInterceptor.ts" />

module NgJwtAuth {

    export declare class Error {
        public name: string;
        public message: string;
        public stack: string;
        constructor(message?: string);
    }

    export class NgJwtAuthException extends Error {

        constructor(public message: string) {
            super(message);
            this.name = 'NgJwtAuthException';
            this.message = message;
            this.stack = (<any>new Error()).stack;
        }
        toString() {
            return this.name + ': ' + this.message;
        }
    }

    export class NgJwtAuthTokenExpiredException extends NgJwtAuthException{}

    export class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {

        private config: INgJwtAuthServiceConfig;

        constructor() {

            //initialise service config
            this.config = {
                tokenLocation: 'token',
                tokenUser: '#user',
                loginController: 'app.public.login',
                apiEndpoints: {
                    base: '/api/auth',
                    login: '/login',
                    tokenExchange: '/token',
                    refresh: '/refresh',
                },
                storageKeyName: 'NgJwtAuthToken',
                refreshBeforeSeconds: 60 * 2, //2 mins
                checkExpiryEverySeconds: 60, //2 mins
            };

        }

        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        public setApiEndpoints(config:IEndpointDefinition) : NgJwtAuthServiceProvider {
            this.config.apiEndpoints = _.defaults(config, this.config.apiEndpoints);
            return this;
        }

        public $get = ['$http', '$q', '$window', '$interval', function NgJwtAuthServiceFactory($http, $q, $window, $interval) {
            return new NgJwtAuthService(this.config, $http, $q, $window, $interval);
        }];

    }



    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
        .service('ngJwtAuthInterceptor', NgJwtAuthInterceptor)
        .config(['$httpProvider', '$injector', ($httpProvider:ng.IHttpProvider) => {

            $httpProvider.interceptors.push('ngJwtAuthInterceptor');
        }])
    ;

    //angular.module('ngJwtAuth.interceptor', [])
    //    .service('ngJwtAuthInterceptor', NgJwtAuthInterceptor)
    //    .config(['$httpProvider', '$injector', ($httpProvider:ng.IHttpProvider) => {
    //
    //        $httpProvider.interceptors.push('ngJwtAuthInterceptor');
    //    }])
    //;


}
