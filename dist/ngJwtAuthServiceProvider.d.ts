import { IEndpointDefinition } from "./ngJwtAuthInterfaces";
import { NgJwtAuthService } from "./ngJwtAuthService";
export declare class Error {
    name: string;
    message: string;
    stack: string;
    constructor(message?: string);
}
export declare class NgJwtAuthException extends Error {
    message: string;
    constructor(message: string);
    toString(): string;
}
export declare class NgJwtAuthTokenExpiredException extends NgJwtAuthException {
}
export declare class NgJwtAuthCredentialsFailedException extends NgJwtAuthException {
}
export declare class NgJwtAuthServiceProvider implements ng.IServiceProvider {
    private config;
    /**
     * Initialise the service provider
     */
    constructor();
    /**
     * Set the configuration
     * @param config
     * @returns {NgJwtAuth.NgJwtAuthServiceProvider}
     */
    configure(config: IEndpointDefinition): NgJwtAuthServiceProvider;
    $get: (string | (($http: any, $q: any, $window: any, $interval: any, base64: any, $cookies: any, $location: any) => NgJwtAuthService))[];
}
