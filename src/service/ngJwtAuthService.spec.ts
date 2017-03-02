import {
    NgJwtAuthServiceProvider, NgJwtAuthException,
    NgJwtAuthCredentialsFailedException
} from "../provider/ngJwtAuthServiceProvider";
import {NgJwtAuthService} from "./ngJwtAuthService";
import {INgJwtAuthServiceConfig, ICredentials, IJwtClaims, IUser} from "../ngJwtAuthInterfaces";

import * as _ from "lodash";
import * as moment from "moment";
import "angular";
import "angular-mocks";
import "../ngJwtAuth";

import {cookiesFactoryMock, locationFactoryMock, fixtures} from "../fixtures.spec"

let expect:Chai.ExpectStatic = chai.expect;

describe('Service tests', () => {

    let $httpBackend:ng.IHttpBackendService;
    let $http:ng.IHttpService;
    let ngJwtAuthService:NgJwtAuthService;
    let $rootScope:ng.IRootScopeService;
    let $cookies:ng.cookies.ICookiesService;
    let $q:ng.IQService;

    window.localStorage.clear();

    let cookieDomain = 'example.com';
    let hostDomain = 'sub.example.com';

    beforeEach(() => {

        angular.mock.module(($provide:ng.auto.IProvideService) => {

            $provide.factory('$cookies', cookiesFactoryMock(cookieDomain));

            $provide.factory('$location', locationFactoryMock(hostDomain));

        });

        angular.module('ngCookies', []); //register the module as being overriden

        angular.mock.module('ngJwtAuth');

        inject((_$httpBackend_, _ngJwtAuthService_, _$http_, _$rootScope_, _$cookies_, _$q_) => {

            $httpBackend = _$httpBackend_;
            $rootScope = _$rootScope_;
            $http = _$http_;
            $q = _$q_;
            $cookies = _$cookies_;

            ngJwtAuthService = _ngJwtAuthService_; //register injected of service provider

        });

        ngJwtAuthService.init();

        let reject = false;
        let loginSuccess = null;

        fixtures.loginPrompt = {
            getLoginSuccessPromise: ():ng.IPromise<any> => {
                return loginSuccess;
            },
            shouldRejectPromise:(shouldRejectPromise:boolean = true) => {
                reject = shouldRejectPromise;
            },
            loginPromptFactory: (deferredCredentials:ng.IDeferred<ICredentials>, loginSuccessPromise:ng.IPromise<IUser>, currentUser:IUser):ng.IPromise<any> => {

                let credentials:ICredentials = {
                    username: fixtures.user.email,
                    password: fixtures.user.password,
                };

                if (reject) {
                    return $q.reject('rejected');
                }

                loginSuccess = loginSuccessPromise; //bind so the tests can attach a spy

                deferredCredentials.notify(credentials);

                loginSuccessPromise.then(() => {
                }, null, (err) => {
                    deferredCredentials.notify(credentials); //retry resolving creds
                });

                return $q.when(true); //immediately resolve
            },
        }

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

            ngJwtAuthService.user = fixtures.userResponse;

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
                return !_.includes(headers, 'Authorization'); //Authorization header has been unset
            }).respond('foobar');

            (<any>ngJwtAuthService).$http.get('/any');

            $httpBackend.flush();

            return expect(ngJwtAuthService.loggedIn).to.be.false;
        })

    });

    describe('Login listening', () => {

        let mockListener;

        beforeEach(() => {
            mockListener = sinon.stub();
            ngJwtAuthService.registerLoginListener(mockListener);
        });

        afterEach(() => {
            mockListener.reset();
        });

        it('should be able to register a login listener', () => {

            expect(mockListener).not.to.have.been.called;

        });

        it('should notify the login listener with the logged in user object', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.deep.equal(fixtures.userResponse);

            $httpBackend.flush();
            $rootScope.$apply();

            expect(mockListener).to.have.been.calledWith(fixtures.userResponse);

        });

    });

    describe('Logout listening', () => {

        let mockListener;

        beforeEach(() => {
            mockListener = sinon.stub();
            ngJwtAuthService.registerLogoutListener(mockListener);
        });

        afterEach(() => {
            mockListener.reset();
        });

        it('should be able to register a logout listener', () => {

            expect(mockListener).not.to.have.been.called;

        });

        it('should notify the logout listener', () => {

            ngJwtAuthService.logout();

            expect(mockListener).to.have.been.called;

        });

    });

    describe('Failed authentication', () => {


        it('should fail promise when server responds with an error code', () => {

            $httpBackend.expectGET('/api/auth/login').respond(404);

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

            $httpBackend.flush();

        });


        it('should fail promise when server responds without a token', () => {

            $httpBackend.expectGET('/api/auth/login').respond({notATokenKey: 'anything'});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

            $httpBackend.flush();

        });


        it('should fail promise when server responds with a non-string token', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: {foo:'bar'}});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

            $httpBackend.flush();

        });

        it('should fail promise when authentication fails', () => {

            $httpBackend.expectGET('/api/auth/login').respond(401);

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuthCredentialsFailedException);

            $httpBackend.flush();

        });

        it('should fail promise when returned token is invalid', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: 'invalid_token'});

            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            expect(authPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

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



        beforeEach(() => {
            sinon.spy(fixtures.loginPrompt, 'loginPromptFactory');
            $q = (<any>ngJwtAuthService).$q;
        });

        afterEach(() => {
            (<any>fixtures.loginPrompt.loginPromptFactory).reset();
        });

        describe('login factory registration', () => {
            it('should throw an exception when a login prompt factory is not set', () => {

                let testLoginPromptFactoryFn = () => {
                    ngJwtAuthService.promptLogin();
                };

                expect(testLoginPromptFactoryFn).to.throw(NgJwtAuthException);

            });

            it('should be able to set a login prompt factory', () => {

                //set credential promise factory
                ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);

                expect(fixtures.loginPrompt.loginPromptFactory).not.to.have.been.called;

            });
        });

        describe('login factory tests', () => {

            beforeEach(() => {

                //set credential promise factory
                ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);
            });

            it('should not be able to re-set a login prompt factory', () => {

                //set credential promise factory
                let setFactoryFn = () => {
                    ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);
                };

                expect(setFactoryFn).to.throw(NgJwtAuthException);

            });

            it('should prompt a login promise to be resolved when a 401 occurs, then retry the method with updated headers', () => {
                $httpBackend.expectGET('/any').respond(401);

                let $http = (<any>ngJwtAuthService).$http; //get the injected http method

                //try to get a resource
                $http.get('/any', {
                    headers: {
                        Authorization: "Bearer " + fixtures.buildToken({signature:'old-token'}),
                    }
                });

                let newToken = fixtures.buildToken({signature:'new-token'});

                $httpBackend.expectGET('/api/auth/login', (headers) => {
                    return headers['Authorization'] == fixtures.authBasic;
                }).respond({token: newToken});

                $httpBackend.expectGET('/any', (headers) => {
                    return headers['Authorization'] == 'Bearer ' + newToken;
                }).respond('ok');

                $httpBackend.flush();

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.been.calledOnce;

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

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.been.calledOnce;

            });

            it.skip('should prompt the login prompt factory for credentials when requested and log out when request rejected', () => {

                fixtures.loginPrompt.shouldRejectPromise(true);

                let userPromise = ngJwtAuthService.promptLogin();

                let loginStatusPromise = userPromise.then(() => {
                    return ngJwtAuthService.loggedIn;
                });

                expect(userPromise).to.eventually.be.rejectedWith('rejected');

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.been.calledOnce;

                expect(loginStatusPromise).eventually.to.be.false;

                fixtures.loginPrompt.shouldRejectPromise(false); //reset

            });

            it('should prompt the login prompt factory for credentials when requested', () => {

                $httpBackend.expectGET('/api/auth/login', (headers) => {
                    return headers['Authorization'] == fixtures.authBasic;
                }).respond({token: fixtures.token});

                let userPromise = ngJwtAuthService.promptLogin();

                expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

                $httpBackend.flush();

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.calledOnce;

            });

            it('should allow the user to retry their credentials when they get them wrong the first time', () => {

                $httpBackend.expectGET('/api/auth/login', (headers) => {
                    return headers['Authorization'] == fixtures.authBasic;
                }).respond(401); //fail their login first time

                $httpBackend.expectGET('/api/auth/login', (headers) => {
                    return headers['Authorization'] == fixtures.authBasic;
                }).respond({token: fixtures.token}); //pass it the second time

                let userPromise = ngJwtAuthService.promptLogin();

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.calledOnce;

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

                expect(fixtures.loginPrompt.loginPromptFactory).to.have.calledOnce;

                let progressSpy = sinon.spy();
                fixtures.loginPrompt.getLoginSuccessPromise().then(null, null, progressSpy);

                userPromise.then(() => {
                    progressSpy.should.have.been.calledTwice;
                    progressSpy.should.have.been.calledWith(sinon.match.instanceOf(NgJwtAuthException));
                    done();
                });

                expect(userPromise).to.eventually.deep.equal(fixtures.userResponse);

                $httpBackend.flush();

            });

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

            expect(refreshFn).to.throw(NgJwtAuthException); //if not logged it, exception should be thrown on attempt to refresh

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

        it('should stop the refresh timer when attempted refresh fails', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});
            ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);
            $httpBackend.flush();

            $httpBackend.expectGET('/api/auth/refresh', (headers) => {
                return headers['Authorization'] == 'Bearer '+fixtures.token;
            }).respond(500);

            let refreshPromise = ngJwtAuthService.refreshToken();

            expect(refreshPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

            refreshPromise.catch(()=>{
                expect((<any>ngJwtAuthService).refreshTimerPromise).to.be.null;
            });

            $httpBackend.flush();

        });

        it('should restart the refresh timer when after failed refresh user re-attempts login', () => {

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});
            ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);
            $httpBackend.flush();

            $httpBackend.expectGET('/api/auth/refresh', (headers) => {
                return headers['Authorization'] == 'Bearer '+fixtures.token;
            }).respond(500);

            let refreshPromise = ngJwtAuthService.refreshToken();

            expect(refreshPromise).to.eventually.be.rejectedWith(NgJwtAuthException);

            $httpBackend.flush();

            $httpBackend.expectGET('/api/auth/login').respond({token: fixtures.token});
            let authPromise = ngJwtAuthService.authenticateCredentials(fixtures.user.email, fixtures.user.password);

            authPromise.then(()=>{
                expect((<any>ngJwtAuthService).refreshTimerPromise).not.to.be.null;
            });

            $httpBackend.flush();

        });

    });

    describe('Get token for known user id', () => {

        beforeEach(() => {
            ngJwtAuthService.logout(); //make sure that the service is not logged in.
        });

        it('should not allow login as user if the user is not logged in already', () => {

            let expectedExceptionFn = () => {

                ngJwtAuthService.loginAsUser('any');
            };

            expect(expectedExceptionFn).to.throw(NgJwtAuthException);
        });

        it('should not be able to retrieve a bearer token if the user is not logged in', () => {

            let expectedExceptionFn = () => {

                //method is private so <any> allows access
                (<any>ngJwtAuthService).getBearerHeader();
            };

            expect(expectedExceptionFn).to.throw(NgJwtAuthException);
        });

        /**
         * Note this feature should be implemented very carefully as it is a security risk as it means users
         * can log in as other users (impersonation). The responsibility is on the implementing app to strongly
         * control permissions to access this endpoint to avoid security risks
         */
        it('should be able to retrieve a token given a known user id', () => {

            //set credential promise factory
            ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);

            let userToImpersonate = fixtures.userResponse;

            userToImpersonate.userId = 2;

            let expectedToken = fixtures.buildToken({
                data: {
                    sub: userToImpersonate.userId,
                    '#user': userToImpersonate
                }
            });

            let validToken = fixtures.token;

            //get the user a valid token
            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: validToken});

            let user = ngJwtAuthService.getPromisedUser();

            $httpBackend.flush();

            expect(user).eventually.to.deep.equal(fixtures.userResponse);

            $httpBackend.expectGET('/api/auth/user/'+userToImpersonate.userId, (headers) => {
                return headers['Authorization'] == 'Bearer ' + validToken;
            }).respond({token: expectedToken});

            let impersonateUserPromise = ngJwtAuthService.loginAsUser(userToImpersonate.userId);

            expect(impersonateUserPromise).to.eventually.deep.equal(userToImpersonate);

            impersonateUserPromise.then(() => {
                expect(ngJwtAuthService.getPromisedUser()).to.eventually.deep.equal(userToImpersonate);
            });

            $httpBackend.flush();

        });

    });

    describe('API Response Authorization update', () => {

        beforeEach(() => {

            //set credential promise factory
            ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);
        });

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



    describe('Cookie interaction', () => {

        let originalConfig:INgJwtAuthServiceConfig;
        let config:INgJwtAuthServiceConfig;

        beforeEach(() => {
            originalConfig = ngJwtAuthService.getConfig();

            //force the configuration to be what we want for cookie tests
            (<any>ngJwtAuthService).config = _.merge(originalConfig, {
                cookie: {
                    enabled: true,
                    name: 'ngJwtAuthToken'
                }
            });

            config = ngJwtAuthService.getConfig();

            //set credential promise factory
            ngJwtAuthService.registerLoginPromptFactory(fixtures.loginPrompt.loginPromptFactory);

        });

        afterEach(() => {
            (<any>ngJwtAuthService).config = originalConfig; //restore
        });

        it('should save a cookie when configured, and remove it when logging out', () => {

            ngJwtAuthService.logout(); //logout

            expect(config.cookie.enabled).to.be.true; //check the service is configured to save cookies

            let token = fixtures.token;

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: token});

            ngJwtAuthService.requireCredentialsAndAuthenticate();

            $rootScope.$apply();

            $httpBackend.flush();

            let cookieExists = $cookies.get(config.cookie.name);

            expect(cookieExists).to.equal(token);

            let expiry = $cookies.getObject(config.cookie.name).conf.expires;

            expect(expiry).to.be.instanceOf(Date);

            ngJwtAuthService.logout(); //logout

            let cookieMissing = $cookies.get(config.cookie.name);

            expect(cookieMissing).to.be.undefined;

        });



        describe('Top level domain saving', () => {


            beforeEach(() => {


                ngJwtAuthService.logout(); //logout

                //force the configuration to have tld = true
                (<any>ngJwtAuthService).config = _.merge(originalConfig, {
                    cookie: {
                        enabled: true,
                        name: 'ngJwtAuthToken',
                        topLevelDomain:true,
                    }
                });


            });

            it('should be able to configure the cookie to be saved to the top level domain', () => {

                expect(config.cookie.enabled).to.be.true; //check the service is configured to save cookies

                let token = fixtures.token;

                $httpBackend.expectGET('/api/auth/login', (headers) => {
                    return headers['Authorization'] == fixtures.authBasic;
                }).respond({token: token});

                ngJwtAuthService.requireCredentialsAndAuthenticate();

                $rootScope.$apply();

                $httpBackend.flush();

                let cookie = $cookies.get(config.cookie.name);

                let cookieObject = $cookies.getObject(config.cookie.name);

                expect(cookie).to.equal(token);
                expect(cookieObject.conf.domain).to.equal(cookieDomain);

            });

            it('should throw exception when storing a cookie fails', () => {

                let expectedExceptionFn = () => {

                    ngJwtAuthService.processNewToken(fixtures.buildToken({
                        signature: 'always-fail-domain'
                    }));

                };

                expect(expectedExceptionFn).to.throw(NgJwtAuthException);

            });

        })


    });

});

describe('Service Reloading', () => {

    let $httpBackend:ng.IHttpBackendService;
    let ngJwtAuthService:NgJwtAuthService;
    let $rootScope:ng.IRootScopeService;
    let defaultAuthServiceProvider:NgJwtAuthServiceProvider;

    beforeEach(()=>{

        angular.mock.module(function ($provide) {

            $provide.factory('$cookies', cookiesFactoryMock('example.com'));

            $provide.factory('$location', locationFactoryMock('sub.example.com'));

        });

        angular.mock.module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
            defaultAuthServiceProvider = _ngJwtAuthServiceProvider_; //register injection of service provider
        });

        inject((_$httpBackend_, _ngJwtAuthService_, _$rootScope_) => {

            $httpBackend = _$httpBackend_;
            $rootScope = _$rootScope_;
            ngJwtAuthService = _ngJwtAuthService_; //register injected of service provider

        });

        let $q = (<any>ngJwtAuthService).$q;


        ngJwtAuthService.registerLoginPromptFactory((deferredCredentials:ng.IDeferred<ICredentials>, loginSuccessPromise:ng.IPromise<IUser>, currentUser:IUser): ng.IPromise<any> => {

            let credentials:ICredentials = {
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


        let clock:Sinon.SinonFakeTimers;

        beforeEach(() => {
            clock = sinon.useFakeTimers();
        });

        afterEach(() => {
            clock.restore();
        });

        it('should not fail when there is no token to load', () => {

            ngJwtAuthService.logout();
            let init = ngJwtAuthService.init();

            $rootScope.$apply(); //force angular to run the promises

            //let some time pass
            let tickIntervalSeconds = 1000;
            clock.tick(1000 * tickIntervalSeconds); //fast forward clock by the configured seconds
            (<any>ngJwtAuthService).$interval.flush(1000 * tickIntervalSeconds); //fast forward intervals by the configured seconds

            expect(init).eventually.to.be.fulfilled;

        });

        it('should fail when the token in storage is malformed (vendor collision perhaps)', () => {

            window.localStorage.setItem((<any>defaultAuthServiceProvider).config.storageKeyName, 'this-is-not-a-jwt-token');

            let init = ngJwtAuthService.init();

            expect(init).eventually.to.be.rejectedWith(sinon.match.instanceOf(NgJwtAuthException));

        });

        it('should use the token from storage on init', () => {

            window.localStorage.setItem((<any>defaultAuthServiceProvider).config.storageKeyName, fixtures.token);

            let userPromise = ngJwtAuthService.init().then(() => ngJwtAuthService.getPromisedUser());

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

            $rootScope.$apply(); //flush the promises before continuing

            $httpBackend.expectGET('/api/auth/refresh', (headers) => {
                return headers['Authorization'] == 'Bearer '+expiringToken;
            }).respond({token: fixtures.token});

            //as angular's $interval does not seem to be overidden by sinon's clock they both have to be ticked independently
            for (let i=0; i<=intervalsToRun;i++){ //add
                clock.tick(1000 * tickIntervalSeconds); //fast forward clock by the configured seconds
                (<any>ngJwtAuthService).$interval.flush(tickIntervalSeconds); //fast forward intervals by the configured seconds


                let latestRefresh = moment((<any>ngJwtAuthService).tokenData.data.exp * 1000).subtract(refreshBeforeSeconds, 'seconds'),
                    nextRefreshOpportunity = moment().add(tickIntervalSeconds)
                ;

                if (latestRefresh <= nextRefreshOpportunity){ //after the interval that the token should have refreshed, flush the http request
                    ngJwtAuthService.refreshToken();
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

    describe('Custom user factory', () => {

        let mockUserFactory = (subClaim:string, tokenData:IJwtClaims):ng.IPromise<IUser> => {

            let user = _.get(tokenData, '#user');
            (<any>user).custom = 'this is a custom property';

            return this.$q.when(user);
        };

        it('should be able to set a user factory', () => {

            ngJwtAuthService.logout();

            $httpBackend.expectGET('/api/auth/login', (headers) => {
                return headers['Authorization'] == fixtures.authBasic;
            }).respond({token: fixtures.token});

            ngJwtAuthService.registerUserFactory(mockUserFactory);

            let user = ngJwtAuthService.getPromisedUser();


            $httpBackend.flush();

            expect(user).eventually.not.to.deep.equal(fixtures.userResponse); //the user should differ from the standard User response
            expect(user).eventually.to.have.property('custom'); //the user should have the new property

        });


    });



});
