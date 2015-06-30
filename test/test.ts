/// <reference path="../typings/tsd.d.ts" />
/// <reference path="../dist/ngJwtAuth.d.ts" />


var expect = chai.expect;

var seededChance = new Chance(1);
var fixtures = {
    user : {
        _self: '/users/1',
        userId: 1,
        email: 'joe.bloggs@example.com',
        firstName: seededChance.first,
        lastName: seededChance.last,
        password: 'password',
        phone: seededChance.phone()
    },

    get authBasic(){
        return 'Basic '+btoa(fixtures.user.email+':'+fixtures.user.password)
    },

    get token(){

        var token:NgJwtAuth.IJwtToken;
        token = {
            header: {
                alg: 'RS256',
                typ: 'JWT'
            },
            data: {
                iss: 'api.spira.io',
                aud: 'spira.io',
                sub: fixtures.user.userId,
                iat: Number(moment().format('X')),
                exp: Number(moment().add(1, 'hours').format('X')),
                jti: 'random-hash',
                '#user': _.omit(fixtures.user, 'password')
            },
            signature: 'this-is-the-signed-hash'
        };

        return btoa(JSON.stringify(token.data))
            + '.' + btoa(JSON.stringify(token.data))
            + '.' + token.signature
        ;

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

    it('should process a token and return a user', () => {

        $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});

        var user;
        ngJwtAuthService.authenticate(fixtures.user.email, fixtures.user.password).then((res) => {
            user = res;
        });

        $httpBackend.flush();

        return expect(user).to.equal(fixtures.user);

    });


});
