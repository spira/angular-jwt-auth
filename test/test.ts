/// <reference path="../typings/tsd.d.ts" />
/// <reference path="../dist/ngJwtAuth.d.ts" />


var expect = chai.expect;

var seededChance = new Chance(1);
var fixtures = {
    user : {
        _self: '/users/1',
        userId: 1,
        email: 'joe.bloggs@example.com',
        firstName: seededChance.first(),
        lastName: seededChance.last(),
        password: 'password',
        phone: seededChance.phone()
    },

    get userResponse(){
        return _.omit(fixtures.user, 'password');
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
                '#user': fixtures.userResponse,
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

    it('should have the default token exchange endpoint', function() {
        expect((<any>defaultAuthService).getTokenExchangeEndpoint()).to.equal('/api/auth/token');
    });

    it('should have the default refresh endpoint', function() {
        expect((<any>defaultAuthService).getRefreshEndpoint()).to.equal('/api/auth/refresh');
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

    describe('Initialisation', () => {

        it('should be an injectable service', () => {

            return expect(ngJwtAuthService).to.be.an('object');
        });

        it('should not be logged in initially', () => {

            return expect(ngJwtAuthService.loggedIn).to.be.false;
        });

        it('should not be able to retrieve a user on init', () => {

            return expect(ngJwtAuthService.getUser()).to.be.undefined;
        });

    });

    describe('Authentication', () => {

        it('should retrieve a json web token', () => {

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});

            let tokenPromise = (<any>ngJwtAuthService).getToken(fixtures.user.email, fixtures.user.password);

            expect(tokenPromise).to.eventually.equal(fixtures.token);

            $httpBackend.flush();

        });

        it('should process a token and return a user', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});

            let authPromise = ngJwtAuthService.authenticate(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();
        });

        it('should be able to get user info once authenticated', () => {

            let user = ngJwtAuthService.getUser();
            let userPromise = ngJwtAuthService.getPromisedUser();

            expect(user).to.deep.equal(fixtures.userResponse);
            expect(userPromise).eventually.to.deep.equal(fixtures.userResponse);

        });

        it('should have saved the jwt to localstorage', () => {

            let storageKey = (<any>ngJwtAuthService).config.storageKeyName;
            expect(window.localStorage.getItem(storageKey)).to.equal(fixtures.token);
        });

        it('should set a default authorisation header for subsequent requests', () => {
            $httpBackend.expectGET('/any', (headers) => {
                return headers['Authorization'] == 'Bearer '+fixtures.token;
            }).respond('foobar');

            (<any>ngJwtAuthService).$http.get('/any');

            $httpBackend.flush();

        });

        it('should be able to log out and clear token data', () => {
            ngJwtAuthService.logout();

            expect(ngJwtAuthService.getUser()).to.be.null;

            $httpBackend.expectGET('/any', (headers) => {
                return !_.contains(headers, 'Authorization'); //Authorization header has been unset
            }).respond('foobar');

            (<any>ngJwtAuthService).$http.get('/any');

            $httpBackend.flush();

            return expect(ngJwtAuthService.loggedIn).to.be.false;
        })

    });

    describe('Failed authentication', () => {


        it('should fail promise when server response with an error code', () => {

            $httpBackend.expectGET('/api/auth/login').respond(404);

            let authPromise = ngJwtAuthService.authenticate(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuth.NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should fail promise when authentication fails', () => {

            $httpBackend.expectGET('/api/auth/login').respond(401);

            let authPromise = ngJwtAuthService.authenticate(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuth.NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should fail promise when returned token is invalid', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: 'invalid_token'});

            let authPromise = ngJwtAuthService.authenticate(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuth.NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should pass through any http errors that are not unauthorised', () => {

            $httpBackend.expectGET('/any').respond(403);

            let $http = (<any>ngJwtAuthService).$http; //get the injected http method

            let httpResponse = $http.get('/any'); //try to get a resource

            expect(httpResponse).to.eventually.be.rejected;

            $httpBackend.flush();

        });

    });

    describe('Require login', () => {

        it('should be able to set a credential promise factory', () => {

            let $q = (<any>ngJwtAuthService).$q;
            //set credential promise factory
            ngJwtAuthService.registerCredentialPromiseFactory((currentUser:NgJwtAuth.IUser) : ng.IPromise<NgJwtAuth.ICredentials> => {
                let credentials:NgJwtAuth.ICredentials = {
                    username: fixtures.user.email,
                    password: fixtures.user.password,
                };

                return $q.when(credentials); //immediately resolve
            });



        });

        it('should not be able to re-set a credential promise factory', () => {

            let $q = (<any>ngJwtAuthService).$q;
            //set credential promise factory
            let setFactoryFn = () => {
                ngJwtAuthService.registerCredentialPromiseFactory((currentUser:NgJwtAuth.IUser):ng.IPromise<NgJwtAuth.ICredentials> => {
                    let credentials:NgJwtAuth.ICredentials = {
                        username: fixtures.user.email,
                        password: fixtures.user.password,
                    };

                    return $q.when(credentials); //immediately resolve
                });
            };


            expect(setFactoryFn).to.throw(NgJwtAuth.NgJwtAuthException);

        });

        it('should prompt a login promise to be resolved when a 401 occurs, then retry the method', () => {
            $httpBackend.expectGET('/any').respond(401);

            let $http = (<any>ngJwtAuthService).$http; //get the injected http method

            $http.get('/any'); //try to get a resource

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});

            $httpBackend.expectGET('/any').respond('ok');

            $httpBackend.flush();
        });


        it('should be able to wait for a user to authenticate to get a user object', () => {

            ngJwtAuthService.logout(); //make sure that the service is not logged in.

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});


            let userPromise = ngJwtAuthService.getPromisedUser();

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

        });

    });


});
