/// <reference path="../typings/tsd.d.ts" />
/// <reference path="../dist/ngJwtAuth.d.ts" />


var expect = chai.expect;

describe('Service Provider Tests', () => {

    var ngJwtAuthServiceProviderObj:NgJwtAuth.NgJwtAuthServiceProvider;
    var defaultAuthServiceObj:NgJwtAuth.NgJwtAuthService;

    describe('Configuration', () => {


        beforeEach(function () {

            angular.module("providers", ['ngJwtAuth']); //require the module as dependency
            module("providers"); //mock the depending module

            module((ngJwtAuthServiceProvider) => {
                ngJwtAuthServiceProviderObj = ngJwtAuthServiceProvider; //register injection of service provider
            });

            inject(function(_ngJwtAuthService_){
                defaultAuthServiceObj = _ngJwtAuthService_;
            }); //complete injection
        });


        it('should configure api endpoints', function () {

            ngJwtAuthServiceProviderObj.setApiEndpoints({
                base: 'mock/base/path/',
                login: 'to/login',
                refresh: 'to/refresh'
            });

            expect((<any>ngJwtAuthServiceProviderObj).config.apiEndpoints.base).to.equal('mock/base/path/');
            expect((<any>ngJwtAuthServiceProviderObj).config.apiEndpoints.login).to.equal('to/login');
            expect((<any>ngJwtAuthServiceProviderObj).config.apiEndpoints.refresh).to.equal('to/refresh');
        });

        it('should have the default endpoints', function() {
            expect((<any>defaultAuthServiceObj).getLoginEndpoint()).to.equal('/api/auth/login');
        });

    });


});
