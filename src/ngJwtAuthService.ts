/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />

module NgJwtAuth {

    export class NgJwtAuthService implements INgJwtAuthService {

        //list injected dependencies
        private $http: ng.IHttpService;

        static $inject = ['$http'];
        constructor($http: ng.IHttpService) {

            _.assign(this, $http); //bind injected dependencies

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
