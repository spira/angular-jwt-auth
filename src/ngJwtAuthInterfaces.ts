/// <reference path="../typings/tsd.d.ts" />

module NgJwtAuth {

    export interface INgJwtAuthService {
        loggedIn: boolean;
        rawToken:string;
        getConfig():INgJwtAuthServiceConfig;
        init():void;
        isLoginMethod(url:string): boolean;
        promptLogin():ng.IPromise<Object>;
        getUser():Object;
        getPromisedUser():ng.IPromise<Object>;
        processNewToken(rawToken:string):ng.IPromise<IUser>;
        loginAsUser(userIdentifier:string|number):ng.IPromise<IUser>;
        authenticateCredentials(username:string, password:string):ng.IPromise<Object>;
        validateToken(rawToken:string):boolean
        exchangeToken(token:string):ng.IPromise<Object>;
        requireCredentialsAndAuthenticate():ng.IPromise<Object>;
        registerLoginPromptFactory(promiseFactory:ILoginPromptFactory):NgJwtAuthService;
        registerUserFactory(userFactory:IUserFactory):NgJwtAuthService;
        logout():void;
    }

    export interface INgJwtAuthServiceProvider {
        configure(config:INgJwtAuthServiceConfig): NgJwtAuthServiceProvider;
    }

    export interface IEndpointDefinition {
        base?: string;
        login?: string;
        loginAsUser?: string;
        tokenExchange?: string;
        refresh?: string;
    }

    export interface ICookieConfig {
        enabled: boolean;
        name?: string;
        topLevelDomain?:boolean;
    }

    export interface INgJwtAuthServiceConfig {
        tokenLocation?: string;
        tokenUser?: string;
        apiEndpoints?: IEndpointDefinition;
        storageKeyName?: string;
        refreshBeforeSeconds?: number;
        checkExpiryEverySeconds?: number;
        cookie?:ICookieConfig;
    }



    export interface IJwtClaims {
        iss: string;
        aud: string;
        sub: string;
        nbf?: number;
        iat: number;
        exp: number;
        jti: string;
    }

    export interface IJwtToken {

        header: {
            alg: string,
            typ: string
        };
        data: IJwtClaims;
        signature: string;
    }

    export interface IUser {
        userId: any;
        email: string;
        firstName?: string;
        lastName?: string;
        emailConfirmed?: string;
        country?: string;
        regionCode?: string;
        avatarImgUrl?: string;
        avatarImgId?: string;
        timezoneIdentifier?: string;
    }

    export interface ICredentials {
        username: string;
        password: string;
    }

    export interface ILoginPromptFactory {
        (deferredCredentials:ng.IDeferred<ICredentials>, loginSuccessPromise:ng.IPromise<IUser>, currentUser:IUser): ng.IPromise<any>;
    }

    export interface IUserFactory {
        (subClaim:string, tokenData:IJwtClaims): ng.IPromise<IUser>;
    }

    export interface ILoginListener {
        (user:IUser):any;
    }

    export interface IBase64Service {
        encode(string:string):string;
        decode(string:string):string;

        urldecode(string:string):string;
        urldecode(string:string):string;
    }

}
