module NgJwtAuth {

    export interface INgJwtAuthService {
        isLoginMethod(url:string, subString:string): boolean;
        getUser():Object;
        getPromisedUser():ng.IPromise<Object>;
        processNewToken(rawToken:string): boolean;
        clearToken():boolean;
        authenticate(username:string, password:string):ng.IPromise<Object>;
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

    export interface IJwtToken {

        header: {
            alg: string,
            typ: string
        },
        data: {
            iss: string;
            aud: string;
            sub: string;
            nbf?: number;
            iat: number;
            exp: number;
            jti: string;
        },
        signature: string
    }

}
