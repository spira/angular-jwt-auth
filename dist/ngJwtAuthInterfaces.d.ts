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
    topLevelDomain?: boolean;
}
export interface INgJwtAuthServiceConfig {
    tokenLocation?: string;
    tokenUser?: string;
    apiEndpoints?: IEndpointDefinition;
    storageKeyName?: string;
    refreshBeforeSeconds?: number;
    checkExpiryEverySeconds?: number;
    cookie?: ICookieConfig;
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
        alg: string;
        typ: string;
    };
    data: IJwtClaims;
    signature: string;
}
export interface IUser {
    userId: any;
    email: string;
    firstName?: string;
    lastName?: string;
}
export interface ICredentials {
    username: string;
    password: string;
}
export interface ILoginPromptFactory {
    (deferredCredentials: ng.IDeferred<ICredentials>, loginSuccessPromise: ng.IPromise<IUser>, currentUser: IUser): ng.IPromise<any>;
}
export interface IUserFactory {
    (subClaim: string, tokenData: IJwtClaims): ng.IPromise<IUser>;
}
export interface IUserEventListener {
    (user: IUser): void;
}
export interface IBase64Service {
    encode(string: string): string;
    decode(string: string): string;
    urldecode(string: string): string;
    urldecode(string: string): string;
}
