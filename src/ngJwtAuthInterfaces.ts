module NgJwtAuth {

    export interface INgJwtAuthService {
        loggedIn: boolean;
        rawToken:string;
        init():void;
        isLoginMethod(url:string): boolean;
        getUser():Object;
        getPromisedUser():ng.IPromise<Object>;
        processNewToken(rawToken:string): IUser;
        authenticateCredentials(username:string, password:string):ng.IPromise<Object>;
        exchangeToken(token:string):ng.IPromise<Object>;
        requireCredentialsAndAuthenticate():ng.IPromise<Object>;
        registerCredentialPromiseFactory(currentUser:IUser):NgJwtAuthService;
        logout():void;
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
        storageKeyName: string;
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
        userId?: any;
        email?: string,
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
