# Angular JSON Web Token Authentication Module
Angular authentication with JSON Web tokens.

[![Build Status](https://travis-ci.org/spira/angular-jwt-auth.svg?branch=master)](https://travis-ci.org/spira/angular-jwt-auth) 
[![Coverage Status](https://coveralls.io/repos/spira/angular-jwt-auth/badge.svg?branch=master)](https://coveralls.io/r/spira/angular-jwt-auth?branch=master)
[![Dependency Status](https://gemnasium.com/spira/angular-jwt-auth.svg)](https://gemnasium.com/spira/angular-jwt-auth)
[![Bower version](https://badge.fury.io/bo/angular-jwt-auth.svg)](http://badge.fury.io/bo/angular-jwt-auth)
[![npm version](https://badge.fury.io/js/angular-jwt-auth.svg)](http://badge.fury.io/js/angular-jwt-auth)

## Intro
This module is for authenticating with a remote REST API, and attaching the auth token to all subsequent `$http` xhr 
 requests to the API.
   
The module has the following features
* Basic (username/password) authentication
* Automatic token refreshing when it is about to expire, 
* Persisting the token to `localstorage` so it is available between sessions
* Token based authentication (useful for authenticating a confirmed registration email).

## Installation

Install through bower:

```sh
bower install angular-jwt-auth --save
```

## Usage

* Require the `ngJwtAuth` module in your angular application

```js
angular.module('app', ['ngJwtAuth'])
```

* (Optionally) configure the service provider

```js
angular.module('app', ['ngJwtAuth'])
.config(['ngJwtAuthServiceProvider', function(ngJwtAuthServiceProvider){
    ngJwtAuthServiceProvider
        .configure({
            tokenLocation: 'token-custom',
            apiEndpoints: {
                base: '/api',
                login: '/login-custom',
                tokenExchange: '/token-custom',
                refresh: '/refresh-custom',
            }
        })
    ;
}])
```

* Inject the `ngJwtAuthService`, initialise it then use it!
The init function loads any existing token from storage and kicks off the $interval that
monitors the expiry status of the token.

It is _highly_ recommended that you register a login prompt factory (See below), as
this will allow the interceptor to prompt your users for their login details when an api
request that returns status code 401.

```js
angular.module('app', ['ngJwtAuth'])
.run(['ngJwtAuthService', function(ngJwtAuthService){
    ngJwtAuthService.init();
}])
.controller('AppCtrl', ['ngJwtAuthService', function(ngJwtAuthService){
    
    $scope.login = function(username, password){
        
        ngJwtAuthService.authenticate(username, password)
            .then(function(authenticatedUser){
                console.log("Login Success!", authenticatedUser);
            })
            .catch(function(err){
                console.error(err);
            })
        
    };
    
}])
```

## Login Prompt Factory
To handle prompting the user for authentication, angular-jwt-auth provides a registration method to allow the application
 to provide a function that resolves a deferred promise for user credentials, and returns a promise that the user has
 attempted authentication.
 The auth service will then attempt to log in with the resolved credentials.
 If an API call returns with a 401 response, the service will intercept the response, and login prompt function will run,
 giving the user a prompt to re-enter their credentials. If their login is successful, the API call that was previously
 rejected will be reattempted.
 
Full typescript example using a modal from [angular materials `$mdDialog`](https://material.angularjs.org/latest/#/api/material.components.dialog/service/$mdDialog) :

Note this example is in typescript, but it is the same in plain javascript.

```ts
module app.guest.login {

    export const namespace = 'app.guest.login';

    class LoginConfig {

        static $inject = ['ngJwtAuthServiceProvider'];
        constructor(private ngJwtAuthServiceProvider:NgJwtAuth.NgJwtAuthServiceProvider){

            let config : NgJwtAuth.INgJwtAuthServiceConfig = {
                refreshBeforeSeconds: 60 * 10, //10 mins
                checkExpiryEverySeconds: 60, //1 min
                apiEndpoints: {
                    base: '/api/auth/jwt',
                    login: '/login',
                    tokenExchange: '/token',
                    refresh: '/refresh',
                },
            };

            ngJwtAuthServiceProvider.configure(config);

        }

    }

    class LoginInit {

        static $inject = ['ngJwtAuthService', '$mdDialog', '$timeout'];
        constructor(
            private ngJwtAuthService:NgJwtAuth.NgJwtAuthService,
            private $mdDialog:ng.material.IDialogService,
            private $timeout:ng.ITimeoutService
        ) {

            ngJwtAuthService
                .registerLoginPromptFactory((deferredCredentials:ng.IDeferred<NgJwtAuth.ICredentials>, loginSuccessPromise:ng.IPromise<NgJwtAuth.IUser>, currentUser:NgJwtAuth.IUser): ng.IPromise<any> => {

                    let dialogConfig:ng.material.IDialogOptions = {
                        templateUrl: 'templates/app/guest/login/login-dialog.tpl.html',
                        controller: namespace+'.controller',
                        clickOutsideToClose: true,
                        locals : {
                            deferredCredentials: deferredCredentials,
                            loginSuccess: {
                                promise: loginSuccessPromise //nest the promise in a function as otherwise material will try to wait for it to resolve
                            },
                        }
                    };

                    return $timeout(_.noop) //first do an empty timeout to allow the controllers to init if login prompt is fired from within a .run() phase
                        .then(() => $mdDialog.show(dialogConfig));

                })
                .init(); //initialise the auth service (kicks off the timers etc)
        }

    }

    interface IScope extends ng.IScope
    {
        login(username:string, password:string):void;
        cancelLoginDialog():void;
        loginError:string;
    }

    class LoginController {

        static $inject = ['$scope', '$mdDialog', 'deferredCredentials', 'loginSuccess'];
        constructor(
            private $scope : IScope,
            private $mdDialog:ng.material.IDialogService,
            private deferredCredentials:ng.IDeferred<NgJwtAuth.ICredentials>,
            private loginSuccess:{promise:ng.IPromise<NgJwtAuth.IUser>}
        ) {

            $scope.loginError = '';

            $scope.login = (username, password) => {

                let credentials:NgJwtAuth.ICredentials = {
                    username: username,
                    password: password,
                };

                deferredCredentials.notify(credentials); //resolve the deferred credentials with the passed creds

                loginSuccess.promise
                    .then(
                        (user) => $mdDialog.hide(user), //on success hide the dialog, pass through the returned user object
                        null,
                        (err:Error) => { //recoverable errors are notified so the user can retry
                            if (err instanceof NgJwtAuth.NgJwtAuthException){
                                $scope.loginError = err.message; //if the is an auth exception, show the value to the user
                            }
                        }
                    )
                ;

            };

            $scope.cancelLoginDialog = () => {
                ngJwtAuthService.logout(); //make sure the user is logged out
                $mdDialog.cancel('closed');
            }; //allow the user to manually close the dialog


        }

    }

    angular.module(namespace, [])
        .config(LoginConfig)
        .run(LoginInit)
        .controller(namespace+'.controller', LoginController);

}
```
