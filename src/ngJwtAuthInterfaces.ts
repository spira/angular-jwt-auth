/// <reference path="../typings/tsd.d.ts" />

module NgJwtAuth {

    export interface INgJwtAuthService {
        loggedIn: boolean;
        rawToken:string;
        init():void;
        isLoginMethod(url:string): boolean;
        promptLogin():ng.IPromise<Object>;
        getUser():Object;
        getPromisedUser():ng.IPromise<Object>;
        processNewToken(rawToken:string): IUser;
        authenticateCredentials(username:string, password:string):ng.IPromise<Object>;
        exchangeToken(token:string):ng.IPromise<Object>;
        requireCredentialsAndAuthenticate():ng.IPromise<Object>;
        registerCredentialPromiseFactory(promiseFactory:ICredentialPromiseFactory):NgJwtAuthService;
        logout():void;
    }

    export interface INgJwtAuthServiceProvider {
        configure(config:INgJwtAuthServiceConfig): NgJwtAuthServiceProvider;
    }

    export interface IEndpointDefinition {
        base?: string;
        login?: string;
        tokenExchange?: string;
        refresh?: string;
    }

    export interface INgJwtAuthServiceConfig {
        tokenLocation?: string;
        tokenUser?: string;
        apiEndpoints?: IEndpointDefinition;
        storageKeyName?: string;
        refreshBeforeSeconds?: number;
        checkExpiryEverySeconds?: number;
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

    export interface IUser {
        userId: any;
        email: string,
        firstName?: string,
        lastName?: string,
    }

    export interface ICredentials {
        username: string;
        password: string;
    }

    export interface ICredentialPromiseFactory {
        (currentUser:IUser): ng.IPromise<ICredentials>;
    }

}
