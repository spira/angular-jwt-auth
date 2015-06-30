/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
/// <reference path="./ngJwtAuthService.ts" />

module NgJwtAuth {

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
                    refresh: '/refresh'
                }
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


        public $get(): INgJwtAuthService {

            return new NgJwtAuthService(null, this.config);
        }

    }

    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
    ;

}
