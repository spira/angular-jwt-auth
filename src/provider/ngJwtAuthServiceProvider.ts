import {INgJwtAuthServiceConfig, IEndpointDefinition} from "../ngJwtAuthInterfaces";
import {NgJwtAuthService} from "../service/ngJwtAuthService";
import * as _ from "lodash";

export declare class Error {
    public name:string;
    public message:string;
    public stack:string;

    constructor(message?:string);
}

export class NgJwtAuthException extends Error {

    constructor(public message:string) {
        super(message);
        this.name = 'NgJwtAuthException';
        this.message = message;
        this.stack = (<any>new Error()).stack;
    }

    toString() {
        return this.name + ': ' + this.message;
    }
}

export class NgJwtAuthTokenExpiredException extends NgJwtAuthException {
}
export class NgJwtAuthCredentialsFailedException extends NgJwtAuthException {
}

export class NgJwtAuthServiceProvider implements ng.IServiceProvider {

    private config:INgJwtAuthServiceConfig;

    /**
     * Initialise the service provider
     */
    constructor() {

        //initialise service config
        this.config = {
            tokenLocation: 'token',
            tokenUser: '#user',
            apiEndpoints: {
                base: '/api/auth',
                login: '/login',
                tokenExchange: '/token',
                loginAsUser: '/user',
                refresh: '/refresh',
            },
            storageKeyName: 'NgJwtAuthToken',
            refreshBeforeSeconds: 60 * 2, //2 mins
            checkExpiryEverySeconds: 60, //2 mins
            cookie: {
                enabled: false,
                name: 'ngJwtAuthToken',
                topLevelDomain: false,
            }
        };

    }

    /**
     * Set the configuration
     * @param config
     * @returns {NgJwtAuthServiceProvider}
     */
    public configure(config:IEndpointDefinition):NgJwtAuthServiceProvider {

        let mismatchedConfig = _.difference(_.keys(config), _.keys(this.config));
        if (mismatchedConfig.length > 0) {
            throw new NgJwtAuthException("Invalid properties [" + mismatchedConfig.join(',') + "] passed to config)");
        }

        this.config = _.defaultsDeep(config, this.config);
        return this;
    }

    public $get = ['$http', '$q', '$window', '$interval', 'base64', '$cookies', '$location', function NgJwtAuthServiceFactory($http, $q, $window, $interval, base64, $cookies, $location) {
        return new NgJwtAuthService(this.config, $http, $q, $window, $interval, base64, $cookies, $location);
    }];

}
