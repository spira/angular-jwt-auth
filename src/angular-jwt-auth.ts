/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />

module AngularJwtAuth {

    export interface IAngularJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser():Object;
        getPromisedUser():angular.IPromise<Object>;
        processNewToken(rawToken:string): boolean;
        clearToken():boolean;
        authenticate(username:string, password:string);
        exchangeToken(token:string):angular.IPromise<Object>;
        requireLogin():angular.IPromise<Object>;
    }

    export interface IAngularJwtAuthServiceProvider {
        setApiEndpoints(config:IEndpointDefinition): AngularJwtAuthServiceProvider;
    }

    export interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }

    export class AngularJwtAuthServiceProvider implements angular.IServiceProvider, IAngularJwtAuthServiceProvider {

        private apiEndpoints : IEndpointDefinition;

        public $http: angular.IHttpService;

        static $inject = ['$http'];

        constructor($http:angular.IHttpService) {

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
         * @returns {AngularJwtAuth.AngularJwtAuthServiceProvider}
         */
        public setApiEndpoints(config:IEndpointDefinition):AngularJwtAuthServiceProvider {
            this.apiEndpoints = _.defaults(config, this.apiEndpoints);
            return this;
        }

        private getRemoteData(url:string){

            var requestConfig = {
                method: 'GET',
                url:  url,
                responseType: 'json'
            };

            return this.$http(requestConfig);

        }


        public $get() {



        }




    }

    angular.module('angularJwtAuth', [])
        .provider('angularJwtAuthService', AngularJwtAuthServiceProvider)
    ;

}