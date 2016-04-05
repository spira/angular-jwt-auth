"use strict";
var NgJwtAuthInterceptor = (function () {
    function NgJwtAuthInterceptor(_$q, _$injector) {
        var _this = this;
        this.getNgJwtAuthService = function () {
            if (_this.ngJwtAuthService == null) {
                _this.ngJwtAuthService = _this.$injector.get('ngJwtAuthService');
            }
            return _this.ngJwtAuthService;
        };
        this.response = function (response) {
            var updateHeader = response.headers('Authorization-Update');
            if (updateHeader) {
                var newToken = updateHeader.replace('Bearer ', '');
                var ngJwtAuthService = _this.getNgJwtAuthService();
                if (!ngJwtAuthService.validateToken(newToken)) {
                    return response; //if it is not a valid JWT, just return the response as it might be some other kind of token that is being updated.
                }
                ngJwtAuthService.processNewToken(newToken);
            }
            return response;
        };
        this.responseError = function (rejection) {
            var ngJwtAuthService = _this.getNgJwtAuthService();
            //if the response is on a login method, reject immediately
            if (ngJwtAuthService.isLoginMethod(rejection.config.url)) {
                return _this.$q.reject(rejection);
            }
            if (401 === rejection.status) {
                return ngJwtAuthService.handleInterceptedUnauthorisedResponse(rejection);
            }
            return _this.$q.reject(rejection);
        };
        this.$q = _$q;
        this.$injector = _$injector;
    }
    /**
     * Construct the service with dependencies injected
     * @param _$q
     * @param _$injector
     */
    NgJwtAuthInterceptor.$inject = ['$q', '$injector'];
    return NgJwtAuthInterceptor;
}());
exports.NgJwtAuthInterceptor = NgJwtAuthInterceptor;
//# sourceMappingURL=ngJwtAuthInterceptor.js.map