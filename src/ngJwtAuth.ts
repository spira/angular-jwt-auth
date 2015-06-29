/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="ngJwtAuthInterfaces.ts" />

module NgJwtAuth {

    export class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {

        private apiEndpoints : IEndpointDefinition;

        //bind injected dependencies
        private $http: ng.IHttpService;

        static $inject = ['$http'];
        constructor($http:ng.IHttpService) {

            _.assign(this, $http); //bind injected dependencies

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

        private getRemoteData(url:string) : ng.IPromise<Object>{

            var requestConfig : ng.IRequestConfig = {
                method: 'GET',
                url:  url,
                responseType: 'json'
            };

            return this.$http(requestConfig);

        }


        public $get(): INgJwtAuthService {

            return new NgJwtAuthService(this.$http);
        }

    }

    class NgJwtAuthService implements INgJwtAuthService {

        //list injected dependencies
        private $http: ng.IHttpService;
        constructor($http: ng.IHttpService) {

            //bind injected dependencies
            this.$http = $http;

        }

        public isLoginMethod(url: string, subString: string) : boolean{
            return true;
        }

        public getUser() : Object{
            return {};
        }
        public getPromisedUser(): ng.IPromise<Object>{
            return this.$http.get('/');
        }

        public processNewToken(rawToken:string) : boolean{
            return true;
        }

        public clearToken():boolean {
            return true;
        }

        public authenticate(username:string, password:string): ng.IPromise<Object>{
            return this.$http.get('/');
        }

        public exchangeToken(token:string):ng.IPromise<Object> {
            return this.$http.get('/');
        }

        public requireLogin():ng.IPromise<Object>{
            return this.$http.get('/');
        }

    }

    angular.module('ngJwtAuth', [])
        .provider('ngJwtAuthService', NgJwtAuthServiceProvider)
    ;

}
