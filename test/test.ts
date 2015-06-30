/// <reference path="../typings/tsd.d.ts" />
/// <reference path="../dist/ngJwtAuth.d.ts" />


var expect = chai.expect;

var fixtures = {
    user : {
        email: 'joe.bloggs@example.com',
        password: 'password'
    },
    get authBasic(){
        return 'Basic '+btoa(fixtures.user.email+':'+fixtures.user.password)
    },
    get token(){

        return 'abc-123';
    }
};

describe('Default configuration', function () {

    var defaultAuthServiceProvider:NgJwtAuth.NgJwtAuthServiceProvider;
    var defaultAuthService:NgJwtAuth.NgJwtAuthService;

    beforeEach(() => {

        module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
            defaultAuthServiceProvider = _ngJwtAuthServiceProvider_; //register injection of service provider
        });

    });

    it('should have the default endpoints', () => {
        expect((<any>defaultAuthServiceProvider).config.apiEndpoints.base).to.equal('/api/auth');
        expect((<any>defaultAuthServiceProvider).config.apiEndpoints.login).to.equal('/login');
        expect((<any>defaultAuthServiceProvider).config.apiEndpoints.refresh).to.equal('/refresh');
    });

    beforeEach(()=>{
        inject(function(_ngJwtAuthService_){
            defaultAuthService = _ngJwtAuthService_;
        })
    });

    it('should have the default login endpoint', function() {
        expect((<any>defaultAuthService).getLoginEndpoint()).to.equal('/api/auth/login');
    });

});

describe('Custom configuration', function () {

    var authServiceProvider:NgJwtAuth.NgJwtAuthServiceProvider;
    var customAuthService:NgJwtAuth.NgJwtAuthService;

    beforeEach(() => {

        module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
            authServiceProvider = _ngJwtAuthServiceProvider_; //register injection of service provider

            authServiceProvider.setApiEndpoints({
                base: 'mock/base/path/',
                login: 'to/login',
                refresh: 'to/refresh'
            });

        });

    });

    it('should have the custom endpoints', () => {
        expect((<any>authServiceProvider).config.apiEndpoints.base).to.equal('mock/base/path/');
        expect((<any>authServiceProvider).config.apiEndpoints.login).to.equal('to/login');
        expect((<any>authServiceProvider).config.apiEndpoints.refresh).to.equal('to/refresh');
    });

    beforeEach(()=>{
        inject((_ngJwtAuthService_) => {
            customAuthService = _ngJwtAuthService_;
        })
    });

    it('should have the configured login endpoint', function() {
        expect((<any>customAuthService).getLoginEndpoint()).to.equal('mock/base/path/to/login');
    });

});


describe('Service tests', () => {

    var $httpBackend:ng.IHttpBackendService;
    var ngJwtAuthService:NgJwtAuth.NgJwtAuthService;

    beforeEach(()=>{

        module('ngJwtAuth');

        inject((_$httpBackend_, _ngJwtAuthService_) => {

            if (!ngJwtAuthService){ //dont rebind, so each test gets the singleton
                $httpBackend = _$httpBackend_;
                ngJwtAuthService = _ngJwtAuthService_; //register injected of service provider
            }
        })
    });

    afterEach(() => {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    it('should be an injectable service', () => {

        return expect(ngJwtAuthService).to.be.an('object');
    });

    it('should retrieve a json web token', () => {

        $httpBackend.expectGET('/api/auth/login', (headers) => {
            return headers['Authorization'] == fixtures.authBasic;
        }).respond({token: fixtures.token});

        var result;
        (<any>ngJwtAuthService).getToken(fixtures.user.email, fixtures.user.password).then((res) => {
            result = res;
        });

        $httpBackend.flush();

        return expect(result).to.equal(fixtures.token);

    });

    it('should process a token', () => {



    });


});
