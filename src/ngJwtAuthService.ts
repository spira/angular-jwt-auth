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

        private getToken(username:string, password:string): ng.IPromise<string>{

            var authHeader = NgJwtAuthService.getAuthHeader(username, password);

            var requestConfig:ng.IRequestConfig = {
                method: 'GET',
                url:  this.getLoginEndpoint(),
                headers: {
                    Authorization : authHeader
                },
                responseType: 'json'
            };

            return this.$http(requestConfig).then((result) => {
                return _.get(result.data, this.config.tokenLocation);
            });
        }

        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        private static readToken(rawToken:string):IJwtToken {

            var jwt:IJwtToken = null;

            var pieces = rawToken.split('.');

            jwt.signature = pieces[2];

            jwt.header = angular.fromJson(atob(pieces[0]));
            jwt.data = angular.fromJson(atob(pieces[1]));

            return jwt;
        }

        public processNewToken(rawToken:string) : boolean{

            try {

                var tokenData = NgJwtAuthService.readToken(rawToken);

                var expiryDate = moment(tokenData.data.exp * 1000);

                var expiryInSeconds = expiryDate.diff(moment(), 'seconds');

                //this.saveTokenToStorage(rawToken, expiryInSeconds);

                //this.setJWTHeader(rawToken);

            }catch(err){
                console.error(err);
                return false;
            }

            return true;

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

        public clearToken():boolean {
            return true;
        }

        /**
         * Attempt to log in with username and password
         * @param username
         * @param password
         * @returns {IPromise<boolean>}
         */
        public authenticate(username:string, password:string):ng.IPromise<Object> {

            return this.getToken(username, password)
                .then((token) => {
                    return this.processNewToken(token);
                })
            ;

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
