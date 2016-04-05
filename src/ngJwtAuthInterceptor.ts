

import {NgJwtAuthService} from "./ngJwtAuthService";

export class NgJwtAuthInterceptor {

    //list injected dependencies
    private $http:ng.IHttpService;
    private $q:ng.IQService;
    private $injector:ng.auto.IInjectorService;
    private ngJwtAuthService:NgJwtAuthService;

    /**
     * Construct the service with dependencies injected
     * @param _$q
     * @param _$injector
     */
    static $inject = ['$q', '$injector'];

    constructor(_$q:ng.IQService, _$injector:ng.auto.IInjectorService) {

        this.$q = _$q;
        this.$injector = _$injector;
    }

    private getNgJwtAuthService = ():NgJwtAuthService=> {
        if (this.ngJwtAuthService == null) {
            this.ngJwtAuthService = <NgJwtAuthService>this.$injector.get('ngJwtAuthService');
        }
        return this.ngJwtAuthService;
    };

    public response = (response:ng.IHttpPromiseCallbackArg<any>):ng.IHttpPromiseCallbackArg<any> => {

        let updateHeader = response.headers('Authorization-Update');

        if (updateHeader) {

            let newToken = updateHeader.replace('Bearer ', '');

            let ngJwtAuthService = this.getNgJwtAuthService();

            if (!ngJwtAuthService.validateToken(newToken)) {
                return response; //if it is not a valid JWT, just return the response as it might be some other kind of token that is being updated.
            }

            ngJwtAuthService.processNewToken(newToken);
        }

        return response;
    };

    public responseError = (rejection):any => {

        let ngJwtAuthService = this.getNgJwtAuthService();

        //if the response is on a login method, reject immediately
        if (ngJwtAuthService.isLoginMethod(rejection.config.url)) {

            return this.$q.reject(rejection);
        }

        if (401 === rejection.status) {

            return ngJwtAuthService.handleInterceptedUnauthorisedResponse(rejection);
        }

        return this.$q.reject(rejection);
    }

}