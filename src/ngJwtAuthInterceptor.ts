module NgJwtAuth {

    export class NgJwtAuthInterceptor {

        //list injected dependencies
        private $http: ng.IHttpService;
        private $q: ng.IQService;
        private $injector: ng.auto.IInjectorService;
        private ngJwtAuthService: NgJwtAuthService;


        /**
         * Construct the service with dependencies injected
         * @param _$q
         * @param _$injector
         */
        static $inject = ['$q', '$injector'];
        constructor(_$q: ng.IQService, _$injector: ng.auto.IInjectorService) {

            this.$q = _$q;
            this.$injector = _$injector;
        }

        private getNgJwtAuthService = (): NgJwtAuthService=> {
            if (this.ngJwtAuthService == null) {
                this.ngJwtAuthService = this.$injector.get('ngJwtAuthService');
            }
            return this.ngJwtAuthService;
        };

        public responseError = (rejection):any => {

            let ngJwtAuthService = this.getNgJwtAuthService();

            //if the response is on a login method, reject immediately
            if (ngJwtAuthService.isLoginMethod(rejection.config.url)){

                return this.$q.reject(rejection);
            }

            if (401 === rejection.status) {

                return ngJwtAuthService.handleInterceptedUnauthorisedResponse(rejection);
            }

            return this.$q.reject(rejection);
        }

    }

}
