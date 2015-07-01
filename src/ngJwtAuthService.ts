/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
/// <reference path="./ngJwtAuthInterfaces.ts" />

module NgJwtAuth {

    export class NgJwtAuthService implements INgJwtAuthService {

        //list injected dependencies
        private $http: ng.IHttpService;
        private $q: ng.IQService;
        private config: INgJwtAuthServiceConfig;

        public loggedIn:boolean = false;
        private user:IUser;

        /**
         * Construct the service with dependencies injected
         * @param _config
         * @param _$http
         * @param _$q
         */
        constructor(_config, _$http: ng.IHttpService, _$q: ng.IQService) {

            this.config = _config;
            this.$http = _$http;
            this.$q = _$q;

        }

        /**
         * Get the endpoint for login
         * @returns {string}
         */
        private getLoginEndpoint():string {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.login;
        }

        /**
         * Get the endpoint for exchanging a token
         * @returns {string}
         */
        private getTokenExchangeEndpoint():string {
            return this.config.apiEndpoints.base + this.config.apiEndpoints.tokenExchange;
        }

        /**
         * Get the endpoint for refreshing a token
         * @returns {string}
         */
        private getRefreshEndpoint():string{
            return this.config.apiEndpoints.base + this.config.apiEndpoints.refresh;
        }

        /**
         * Build a authentication basic header string
         * @param username
         * @param password
         * @returns {string}
         */
        private static getAuthHeader(username:string, password:string):string{
            return 'Basic ' + btoa(username + ':' + password); //note btoa is NOT supported <= IE9
        }

        /**
         * Retrieve the token from the remote API
         * @param username
         * @param password
         * @returns {IPromise<TResult>}
         */
        private getToken(username:string, password:string): ng.IPromise<any>{

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
            })
            .catch((result) => {

                if (result.status === 401){
                    //throw new NgJwtAuthException("Login attempt received unauthorised response");
                    return this.$q.reject(new NgJwtAuthException("Login attempt received unauthorised response"));
                }

                //throw new NgJwtAuthException("The API reported an error");
                return this.$q.reject(new NgJwtAuthException("The API reported an error"));
            });
        }

        /**
         * Parse the raw token
         * @param rawToken
         * @returns {IJwtToken}
         */
        private static readToken(rawToken:string):IJwtToken {

            if ((rawToken.match(/\./g) || []).length !== 2){
                throw new NgJwtAuthException("Raw token is has incorrect format. Format must be of form \"[header].[data].[signature]\"");
            }

            var pieces = rawToken.split('.');

            var jwt:IJwtToken = {
                header : angular.fromJson(atob(pieces[0])),
                data : angular.fromJson(atob(pieces[1])),
                signature : pieces[2],
            };

            return jwt;
        }

        /**
         * Read and save the raw token to storage, kick off timer to attempt refresh
         * @param rawToken
         * @returns {IUser}
         */
        public processNewToken(rawToken:string) : IUser{


            var tokenData = NgJwtAuthService.readToken(rawToken);

            var expiryDate = moment(tokenData.data.exp * 1000);

            var expiryInSeconds = expiryDate.diff(moment(), 'seconds');

            //this.saveTokenToStorage(rawToken, expiryInSeconds);

            //this.setJWTHeader(rawToken);

            return this.getUserFromTokenData(tokenData);

        }

        /**
         * Check if the endpoint is a login method (used for skipping the authentication error interceptor)
         * @param url
         * @returns {boolean}
         */
        public isLoginMethod(url: string) : boolean{

            let loginMethods = [
                this.getLoginEndpoint(),
                this.getTokenExchangeEndpoint(),
            ];

            return _.contains(loginMethods, url);
        }

        public getUser() : IUser{
            return this.user;
        }

        /**
         *
         * @returns {IHttpPromise<T>}
         */
        public getPromisedUser(): ng.IPromise<IUser>{

            if (this.loggedIn){ //if we are already logged in, resolve the user immediately
                return this.$q.when(this.user);
            }else{ //otherwise require login then return the user
                return this.requireLogin()
                    .then(function(){
                        return this.getUser();
                    })
                ;
            }

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
        public authenticate(username:string, password:string):ng.IPromise<any> {

            return this.getToken(username, password)
                .then((token) => {

                    try {
                        this.user = this.processNewToken(token);

                        this.loggedIn = true;

                        return this.user;
                    }catch(error){
                        return this.$q.reject(error);
                    }

                })
            ;

        }

        public exchangeToken(token:string):ng.IPromise<Object> {
            return this.$http.get('/');
        }

        public requireLogin():ng.IPromise<Object>{
            return this.$http.get('/');
        }

        /**
         * Find the user object within the path
         * @todo resolve the return type assignment with _.get
         * @param tokenData
         * @returns {T}
         */
        private getUserFromTokenData(tokenData:IJwtToken):IUser {

            return _.get(tokenData.data, this.config.tokenUser);
        }
    }

}
