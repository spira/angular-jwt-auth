/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />
/// <reference path="./ngJwtAuthService.ts" />

module NgJwtAuth {

    export class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {

        public apiEndpoints : IEndpointDefinition;

        constructor() {

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
        public setApiEndpoints(config:IEndpointDefinition) : NgJwtAuthServiceProvider {
            this.apiEndpoints = _.defaults(config, this.apiEndpoints);
            return this;
        }


        public $get(): INgJwtAuthService {

            return new NgJwtAuthService(null);
        }

    }

    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
    ;

}
