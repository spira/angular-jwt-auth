/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />
declare module NgJwtAuth {
    interface INgJwtAuthService {
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): boolean;
        clearToken(): boolean;
        authenticate(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
    }
    interface INgJwtAuthServiceProvider {
        setApiEndpoints(config: IEndpointDefinition): NgJwtAuthServiceProvider;
    }
    interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }
}
declare module NgJwtAuth {
    class NgJwtAuthService implements INgJwtAuthService {
        private $http;
        static $inject: string[];
        constructor($http: ng.IHttpService);
        isLoginMethod(url: string, subString: string): boolean;
        getUser(): Object;
        getPromisedUser(): ng.IPromise<Object>;
        processNewToken(rawToken: string): boolean;
        clearToken(): boolean;
        authenticate(username: string, password: string): ng.IPromise<Object>;
        exchangeToken(token: string): ng.IPromise<Object>;
        requireLogin(): ng.IPromise<Object>;
        private getRemoteData(url);
    }
}
declare module NgJwtAuth {
    class NgJwtAuthServiceProvider implements ng.IServiceProvider, INgJwtAuthServiceProvider {
        apiEndpoints: IEndpointDefinition;
        constructor();
        /**
         * Set the API endpoints for the auth service to call
         * @param config
         * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
         */
        setApiEndpoints(config: IEndpointDefinition): NgJwtAuthServiceProvider;
        $get(): INgJwtAuthService;
    }
}
