module NgJwtAuth {

    export interface INgJwtAuthService {
        isLoginMethod(url:string, subString:string): boolean;
        getUser():Object;
        getPromisedUser():ng.IPromise<Object>;
        processNewToken(rawToken:string): boolean;
        clearToken():boolean;
        getToken(username:string, password:string):ng.IPromise<string>;
        exchangeToken(token:string):ng.IPromise<Object>;
        requireLogin():ng.IPromise<Object>;
    }

    export interface INgJwtAuthServiceProvider {
        setApiEndpoints(config:IEndpointDefinition): NgJwtAuthServiceProvider;
    }

    export interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }

    export interface INgJwtAuthServiceConfig {
        tokenLocation: string;
        tokenUser: string;
        loginController: string;
        apiEndpoints: IEndpointDefinition;
    }


}
