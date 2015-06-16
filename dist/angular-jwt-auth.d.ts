/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module AngularJwtAuth {
    interface IAngularJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): angular.IPromise<Object>;
        processNewToken(rawToken: string): boolean;
        clearToken(): boolean;
        authenticate(username: string, password: string): any;
        exchangeToken(token: string): angular.IPromise<Object>;
        requireLogin(): angular.IPromise<Object>;
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
    class AngularJwtAuthServiceProvider implements angular.IServiceProvider, IAngularJwtAuthServiceProvider {
        private apiEndpoints;
        $http: angular.IHttpService;
        static $inject: string[];
        constructor($http: angular.IHttpService);
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {AngularJwtAuth.AngularJwtAuthService}
         */
        setApiEndpoints(config: IEndpointDefinition): AngularJwtAuthServiceProvider;
        private getRemoteData(url);
        $get(): void;
    }
}
