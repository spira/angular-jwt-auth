export declare class NgJwtAuthInterceptor {
    private $http;
    private $q;
    private $injector;
    private ngJwtAuthService;
    /**
     * Construct the service with dependencies injected
     * @param _$q
     * @param _$injector
     */
    static $inject: string[];
    constructor(_$q: ng.IQService, _$injector: ng.auto.IInjectorService);
    private getNgJwtAuthService;
    response: (response: ng.IHttpPromiseCallbackArg<any>) => ng.IHttpPromiseCallbackArg<any>;
    responseError: (rejection: any) => any;
}
