/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module AngularJwtAuth {
    interface IAngularJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): boolean;
        clearToken(): boolean;
        authenticate(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
    }
    interface IAngularJwtAuthServiceProvider {
        setApiEndpoints(config: IEndpointDefinition): AngularJwtAuthServiceProvider;
    }
    interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }
    class AngularJwtAuthServiceProvider implements ng.IServiceProvider, IAngularJwtAuthServiceProvider {
        private apiEndpoints;
        private $http;
        static $inject: string[];
        constructor($http: ng.IHttpService);
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {AngularJwtAuth.AngularJwtAuthServiceProvider}
         */
        setApiEndpoints(config: IEndpointDefinition): AngularJwtAuthServiceProvider;
        private getRemoteData(url);
        $get(): IAngularJwtAuthService;
    }
}
