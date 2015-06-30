/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />

module NgJwtAuth {

    export class NgJwtAuthService implements INgJwtAuthService {

        //list injected dependencies
        private $http: ng.IHttpService;
        private config: INgJwtAuthServiceConfig;

        constructor(_config, _$http: ng.IHttpService) {

            this.config = _config;
            this.$http = _$http;

        }

        private getLoginEndpoint():string {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.login;
        }

        private getTokenExchangeEndpoint():string {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.tokenExchange;
        }

        private getRefreshEndpoint():string{
            return this.config.apiEndpoints.base + this.config.apiEndpoints.refresh;
        }

        private static getAuthHeader(username:string, password:string):string{
            return 'Basic ' + btoa(username + ':' + password); //note btoa is NOT supported <= IE9
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

            var authHeader = NgJwtAuthService.getAuthHeader(username, password);

            var requestConfig:ng.IRequestConfig = {
                method: 'GET',
                url:  this.getLoginEndpoint(),
                headers: {
                    Authorization : authHeader
                },
                responseType: 'json'
            };

            return this.$http(requestConfig);
        }

        public exchangeToken(token:string):ng.IPromise<Object> {
            return this.$http.get('/');
        }

        public requireLogin():ng.IPromise<Object>{
            return this.$http.get('/');
        }

        private getRemoteData(url:string) : ng.IPromise<Object>{

          var requestConfig : ng.IRequestConfig = {
            method: 'GET',
            url:  url,
            responseType: 'json'
          };

          return this.$http(requestConfig);

        }

    }

}
