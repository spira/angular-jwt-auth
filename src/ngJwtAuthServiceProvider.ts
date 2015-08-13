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
    export class NgJwtAuthCredentialsFailedException extends NgJwtAuthException{}

    export class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {

        private config: INgJwtAuthServiceConfig;

        /**
         * Initialise the service provider
         */
        constructor() {

            //initialise service config
            this.config = {
                tokenLocation: 'token',
                tokenUser: '#user',
                apiEndpoints: {
                    base: '/api/auth',
                    login: '/login',
                    tokenExchange: '/token',
                    refresh: '/refresh',
                },
                storageKeyName: 'NgJwtAuthToken',
                refreshBeforeSeconds: 60 * 2, //2 mins
                checkExpiryEverySeconds: 60, //2 mins
                cookie: {
                    enabled: false,
                    name: 'ngJwtAuthToken',
                    removeFromHeader: true
                }
            };

        }

        /**
         * Set the configuration
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        public configure(config:IEndpointDefinition) : NgJwtAuthServiceProvider {

            let mismatchedConfig = _.difference(_.keys(config), _.keys(this.config));
            if (mismatchedConfig.length > 0){
                throw new NgJwtAuthException("Invalid properties ["+mismatchedConfig.join(',')+"] passed to config)");
            }

            this.config = _.defaults(config, this.config);
            return this;
        }

        public $get = ['$http', '$q', '$window', '$interval', 'base64', '$cookies', function NgJwtAuthServiceFactory($http, $q, $window, $interval, base64, $cookies) {
            return new NgJwtAuthService(this.config, $http, $q, $window, $interval, base64, $cookies);
        }];

    }



    angular.module('ngJwtAuth', ['ab-base64', 'ngCookies'])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
        .service('ngJwtAuthInterceptor', NgJwtAuthInterceptor)
        .config(['$httpProvider', '$injector', ($httpProvider:ng.IHttpProvider) => {

            $httpProvider.interceptors.push('ngJwtAuthInterceptor');
        }])
    ;

}
