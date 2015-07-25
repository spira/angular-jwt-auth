/// <reference path="../typings/tsd.d.ts" />
/// <reference path="../dist/ngJwtAuth.d.ts" />


let expect = chai.expect;

let seededChance = new Chance(1);
let fixtures = {
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

    buildToken: (overrides = {}) => {
        let defaultConfig = {
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

        let token:NgJwtAuth.IJwtToken = <any>_.merge(defaultConfig, overrides);

        return btoa(JSON.stringify(token.data))
            + '.' + btoa(JSON.stringify(token.data))
            + '.' + token.signature
        ;
    },

    get token(){

        return fixtures.buildToken(); //no customisations
    }
};

let defaultAuthServiceProvider:NgJwtAuth.NgJwtAuthServiceProvider;

describe('Default configuration', function () {

    let defaultAuthService:NgJwtAuth.NgJwtAuthService;

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

    let authServiceProvider:NgJwtAuth.NgJwtAuthServiceProvider;
    let customAuthService:NgJwtAuth.NgJwtAuthService;
    let partialCustomConfig:NgJwtAuth.INgJwtAuthServiceConfig = {
        tokenLocation: 'token-custom',
        tokenUser: '#user-custom',
        apiEndpoints: {
            base: '/api/auth-custom',
            login: '/login-custom',
            tokenExchange: '/token-custom',
            refresh: '/refresh-custom',
        },
        //storageKeyName: 'NgJwtAuthToken-custom', //intentionally commented out as this will be tested to be the default
    };

    beforeEach(() => {

        module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
            authServiceProvider = _ngJwtAuthServiceProvider_; //register injection of service provider

            authServiceProvider.configure(partialCustomConfig);
        });

    });

    it('should throw an exception when invalid configuration is passed', () => {

        let testInvalidConfigurationFn = () => {
            authServiceProvider.configure(<any>{invalid:'config'});
        };

        expect(testInvalidConfigurationFn).to.throw(NgJwtAuth.NgJwtAuthException);

    });

    it('should be able to partially configure the service provider', () => {

        expect((<any>authServiceProvider).config.apiEndpoints).to.deep.equal(partialCustomConfig.apiEndpoints); //assert that the custom value has come across

        expect((<any>authServiceProvider).config.storageKeyName).to.deep.equal((<any>authServiceProvider).config.storageKeyName); //assert that the default was not overridden

    });

    beforeEach(()=>{
        inject((_ngJwtAuthService_) => {
            customAuthService = _ngJwtAuthService_;
        })
    });

    it('should have the configured login endpoint', function() {
        expect((<any>customAuthService).getLoginEndpoint()).to.equal('/api/auth-custom/login-custom');
    });

});


describe('Service tests', () => {

    let $httpBackend:ng.IHttpBackendService;
    let $http:ng.IHttpService;
    let ngJwtAuthService:NgJwtAuth.NgJwtAuthService;
    let $rootScope:ng.IRootScopeService;

    window.localStorage.clear();

    beforeEach(()=>{

        module('ngJwtAuth');

        inject((_$httpBackend_, _ngJwtAuthService_, _$http_, _$rootScope_) => {

            if (!ngJwtAuthService){ //dont rebind, so each test gets the singleton
                $httpBackend = _$httpBackend_;
                $rootScope = _$rootScope_;
                ngJwtAuthService = _ngJwtAuthService_; //register injected of service provider
                $http = _$http_;
            }
        });

        ngJwtAuthService.init();

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

        it('should process a token and return a user', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

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

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuth.NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should fail promise when authentication fails', () => {

            $httpBackend.expectGET('/api/auth/login').respond(401);

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuth.NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should fail promise when returned token is invalid', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: 'invalid_token'});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

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

    describe('Login prompt', () => {

        let $q;
        let rejectPromise = false;
        let loginSuccess:ng.IPromise<any> = null;
        let spy = {
            loginPromptFactory: (deferredCredentials:ng.IDeferred<NgJwtAuth.ICredentials>, loginSuccessPromise:ng.IPromise<NgJwtAuth.IUser>, currentUser:NgJwtAuth.IUser): ng.IPromise<any> => {

                let credentials:NgJwtAuth.ICredentials = {
                    username: fixtures.user.email,
                    password: fixtures.user.password,
                };

                if (rejectPromise){
                    return $q.reject('rejected');
                }

                loginSuccess = loginSuccessPromise; //bind so the tests can attach a spy

                deferredCredentials.notify(credentials);

                loginSuccessPromise.then(() => {
                }, null, (err) => {
                    deferredCredentials.notify(credentials); //retry resolving creds
                });

                return $q.when(true); //immediately resolve
            }
        };

        sinon.spy(spy, 'loginPromptFactory');

        beforeEach(() => {
            $q = (<any>ngJwtAuthService).$q;
        });

        it('should throw an exception when a login prompt factory is not set', () => {

            let testLoginPromptFactoryFn = () => {
                ngJwtAuthService.promptLogin();
            };

            expect(testLoginPromptFactoryFn).to.throw(NgJwtAuth.NgJwtAuthException);

        });

        it('should be able to set a login prompt factory', () => {

            //set credential promise factory
            ngJwtAuthService.registerLoginPromptFactory(spy.loginPromptFactory);

            expect(spy.loginPromptFactory).not.to.have.been.called;

        });

        it('should not be able to re-set a login prompt factory', () => {

            //set credential promise factory
            let setFactoryFn = () => {
                ngJwtAuthService.registerLoginPromptFactory(() => $q.when(true));
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

            expect(spy.loginPromptFactory).to.have.been.calledOnce;

        });


        it('should be able to wait for a user to authenticate to get a user object', () => {

            ngJwtAuthService.logout(); //make sure that the service is not logged in.

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});


            let userPromise = ngJwtAuthService.getPromisedUser();

            let loginStatusPromise = userPromise.then(() => {
                return ngJwtAuthService.loggedIn;
            });

            expect(loginStatusPromise).eventually.to.be.true;

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

            expect(spy.loginPromptFactory).to.have.been.calledTwice;

        });

        it('should prompt the login prompt factory for credentials when requested and log out when request rejected', () => {

            rejectPromise = true;

            let userPromise = ngJwtAuthService.promptLogin();

            let loginStatusPromise = userPromise.then(() => {
                return ngJwtAuthService.loggedIn;
            });

            expect(userPromise).to.eventually.be.rejectedWith('rejected');

            expect(spy.loginPromptFactory).to.have.been.calledThrice;

            expect(loginStatusPromise).eventually.to.be.false;

        });

        it('should prompt the login prompt factory for credentials when requested', () => {

            rejectPromise = false;

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});

            let userPromise = ngJwtAuthService.promptLogin();

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

            expect(spy.loginPromptFactory).to.have.callCount(4);

        });

        it('should allow the user to retry their credentials when they get them wrong the first time', () => {

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond(401); //fail their login first time

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token}); //pass it the second time

            let userPromise = ngJwtAuthService.promptLogin();

            expect(spy.loginPromptFactory).to.have.callCount(5);

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

        });

        it('should have only one error notification emitted for each repeated credential failure', (done) => {

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond(401); //fail their login first time

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond(401); //fail their login a second time

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token}); //pass it on the third go

            let userPromise = ngJwtAuthService.promptLogin();

            expect(spy.loginPromptFactory).to.have.callCount(6);

            var progressSpy = sinon.spy();
            loginSuccess.then(null, null, progressSpy);

            userPromise.then(() => {
                progressSpy.should.have.been.calledTwice;
                progressSpy.should.have.been.calledWith(sinon.match.instanceOf(NgJwtAuth.NgJwtAuthException));
                done();
            });

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

        });

    });


    describe('Authenticate with token', () => {

        beforeEach(() => {
            ngJwtAuthService.logout(); //make sure that the service is not logged in.
        });

        it ('should be able to authenticate with an arbitrary token', () => {

            let token = 'abc123';

            $httpBackend.expectGET('/api/auth/token', (headers) => {
                return headers['Authorization'] == 'Token '+token;
            }).respond({token: fixtures.token});


            let authPromise = ngJwtAuthService.exchangeToken(token);

            expect(authPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();

        });

        it ('should be able to re-authenticate with an existing token', () => {

            let refreshFn = () => {
                ngJwtAuthService.refreshToken();
            };

            expect(refreshFn).to.throw(NgJwtAuth.NgJwtAuthException); //if not logged it, exception should be thrown on attempt to refresh

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});
            ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);
            $httpBackend.flush();

            let updatedToken = fixtures.buildToken({signature:'update-hash'});

            $httpBackend.expectGET('/api/auth/refresh', (headers) => {
                return headers['Authorization'] == 'Bearer '+fixtures.token;
            }).respond({token: updatedToken});

            let refreshPromise = ngJwtAuthService.refreshToken();

            expect(refreshPromise).to.eventually.be.fulfilled;

            refreshPromise.then(()=>{
                expect(ngJwtAuthService.rawToken).to.equal(updatedToken);
            });

            $httpBackend.flush();

        });

    });




    describe('API Response Authorization update', () => {


        it('should update the request header when an Authorization-Update header is received', () => {


            ngJwtAuthService.logout(); //make sure user is logged out
            let validToken = fixtures.token;

            //get the user a valid token
            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: validToken});

            let user = ngJwtAuthService.getPromisedUser();

            $httpBackend.flush();

            expect(user).eventually.to.deep.equal(fixtures.userResponse);

            let newHeader = fixtures.buildToken({data:{jti:'updated-token'}});

            $httpBackend.expectGET('/any', (headers) => {
                return headers['Authorization'] == 'Bearer '+validToken;
            }).respond('foo', {
                'Authorization-Update': 'Bearer ' + newHeader,
            });

            $http.get('/any');

            $httpBackend.flush();

            expect(ngJwtAuthService.rawToken).to.equal(newHeader);

            $httpBackend.expectGET('/any', (headers) => {
                return headers['Authorization'] == 'Bearer '+newHeader;
            }).respond('bar');

            (<any>ngJwtAuthService).$http.get('/any');

            $httpBackend.flush();

        });

        it('should allow another api to define a non-jwt Authorization-Update header without throwing an error', () => {

            $httpBackend.expectGET('/any').respond('foo', {
                'Authorization-Update': 'Bearer ' + 'some-other-token',
            });

            let result = $http.get('/any');

            $httpBackend.flush();

            expect(result).eventually.to.have.deep.property('data', 'foo');

        });

    });

});

describe('Service Reloading', () => {

    let $httpBackend:ng.IHttpBackendService;
    let ngJwtAuthService:NgJwtAuth.NgJwtAuthService;

    beforeEach(()=>{

        module('ngJwtAuth');

        inject((_$httpBackend_, _ngJwtAuthService_) => {

            $httpBackend = _$httpBackend_;
            ngJwtAuthService = _ngJwtAuthService_; //register injected of service provider

        });

        let $q = (<any>ngJwtAuthService).$q;


        ngJwtAuthService.registerLoginPromptFactory((deferredCredentials:ng.IDeferred<NgJwtAuth.ICredentials>, loginSuccessPromise:ng.IPromise<NgJwtAuth.IUser>, currentUser:NgJwtAuth.IUser): ng.IPromise<any> => {

            let credentials:NgJwtAuth.ICredentials = {
                username: fixtures.user.email,
                password: fixtures.user.password,
            };

            deferredCredentials.notify(credentials);

            return $q.when(true); //immediately resolve
        });

    });

    afterEach(() => {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('User reloaded before expiry', () => {


        let clock:Sinon.SinonFakeTimers = sinon.useFakeTimers();

        after(() => {
            clock.restore();
        });

        it('should use the token from storage on init', () => {

            window.localStorage.setItem((<any>defaultAuthServiceProvider).config.storageKeyName, fixtures.token);

            ngJwtAuthService.init();

            let userPromise = ngJwtAuthService.getPromisedUser();

            expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);
            return expect(ngJwtAuthService.loggedIn).to.be.true;

        });

        it('should refresh the token when it is about to expire', () => {

            let tokenExpirySeconds = 60 * 20; //20 mins

            let expiringToken = fixtures.buildToken({
                data: {
                    exp: moment().add(tokenExpirySeconds, 'seconds').format('X')
                },
                signature: 'nearly-expired-token'
            });

            window.localStorage.setItem((<any>ngJwtAuthService).config.storageKeyName, expiringToken);

            let tickIntervalSeconds = (<any>ngJwtAuthService).config.checkExpiryEverySeconds,
                refreshBeforeSeconds = (<any>ngJwtAuthService).config.refreshBeforeSeconds,
                intervalsToRun = (tokenExpirySeconds / tickIntervalSeconds) + 10 //make sure at least the expiry period is ticked over
            ;

            ngJwtAuthService.init(); //initialise with the default token

            $httpBackend.expectGET('/api/auth/refresh', (headers) => {
                return headers['Authorization'] == 'Bearer '+expiringToken;
            }).respond({token: fixtures.token});

            //as angular's $interval does not seem to be overidden by sinon's clock they both have to be ticked independently
            for (let i=0; i<=intervalsToRun;i++){ //add
                clock.tick(1000 * tickIntervalSeconds); //fast forward clock by the configured seconds
                (<any>ngJwtAuthService).$interval.flush(1000 * tickIntervalSeconds); //fast forward intervals by the configured seconds


                let latestRefresh = moment((<any>ngJwtAuthService).tokenData.data.exp * 1000).subtract(refreshBeforeSeconds, 'seconds'),
                    nextRefreshOpportunity = moment().add(tickIntervalSeconds)
                ;

                if (latestRefresh <= nextRefreshOpportunity){ //after the interval that the token should have refreshed, flush the http request
                    $httpBackend.flush();
                }

            }

            return expect(ngJwtAuthService.loggedIn).to.be.true;

        });

        it('should not attempt to refresh the token over time when the user has never logged in', () => {

            ngJwtAuthService.logout(); //make sure user is logged out

            let tickIntervalSeconds = (<any>ngJwtAuthService).config.checkExpiryEverySeconds,
                hoursToRun = 4,
                intervalsToRun = (hoursToRun*60*60) / tickIntervalSeconds
            ;

            ngJwtAuthService.init(); //initialise without a token

            //as angular's $interval does not seem to be overidden by sinon's clock they both have to be ticked independently
            for (let i=0; i <= intervalsToRun;i++){ //add

                clock.tick(1000 * tickIntervalSeconds); //fast forward clock by the configured seconds
                (<any>ngJwtAuthService).$interval.flush(1000 * tickIntervalSeconds); //fast forward intervals by the configured seconds

            }

            return expect(ngJwtAuthService.loggedIn).to.be.false;

        });

    });

    describe('User reloaded after expiry', () => {

        let expiredToken = fixtures.buildToken({
            data: {
                exp: moment().subtract(1, 'hour').format('X')
            },
            signature: 'expired-token'
        });

        before(()=>{
            ngJwtAuthService.logout(); //clear the authservice state
            window.localStorage.setItem((<any>defaultAuthServiceProvider).config.storageKeyName, expiredToken);
        });

        it('should prompt the user to log in when the loaded token has expired on init', () => {

            //after prompt the credentials are immediately supplied, triggering a new auth request
            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});

            ngJwtAuthService.init();

            $httpBackend.flush();

            let user = ngJwtAuthService.getUser();

            expect(user).to.deep.equal(fixtures.userResponse);
            expect(ngJwtAuthService.rawToken).to.not.equal(expiredToken);

        });

    });



});
