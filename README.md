# Angular JSON Web Token Authentication Module
Angular authentication with JSON Web tokens.

[![Build Status](https://travis-ci.org/spira/angular-jwt-auth.svg?branch=master)](https://travis-ci.org/spira/angular-jwt-auth) 
[![Coverage Status](https://coveralls.io/repos/spira/angular-jwt-auth/badge.svg?branch=master)](https://coveralls.io/r/spira/angular-jwt-auth?branch=master)
[![Dependency Status](https://gemnasium.com/spira/angular-jwt-auth.svg)](https://gemnasium.com/spira/angular-jwt-auth)
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

Install through npm:

```sh
npm install angular-jwt-auth --save
```

## Usage

* Require the `ngJwtAuth` module in your angular application

```ts
import "angular"
import "angular-jwt-auth"
angular.module('app', ['ngJwtAuth'])
```

* (Optionally) configure the service provider

```ts

import {NgJwtAuthServiceProvider} from "angular-jwt-auth"

angular.module('app', ['ngJwtAuth'])
.config(['ngJwtAuthServiceProvider', function(ngJwtAuthServiceProvider:NgJwtAuthServiceProvider){
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

```ts
angular.module('app', ['ngJwtAuth'])
.run(['ngJwtAuthService', function(ngJwtAuthService){
    ngJwtAuthService.init();
}])
.controller('AppCtrl', ['$scope', 'ngJwtAuthService', function($scope, ngJwtAuthService){
    
    $scope.login = function(username, password){
        
        ngJwtAuthService.authenticateCredentials(username, password)
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
 
Full typescript example from the [Spira](https://github.com/spira/spira) project using a modal from [angular materials `$mdDialog`](https://material.angularjs.org/latest/#/api/material.components.dialog/service/$mdDialog) :

Note this example is in typescript, but it is the same process in plain javascript.

```ts
namespace app.guest.login {

    export const namespace = 'app.guest.login';

    class LoginConfig {

        static $inject:string[] = ['ngJwtAuthServiceProvider',];
        constructor(private ngJwtAuthServiceProvider:NgJwtAuthServiceProvider) {
    
            ngJwtAuthServiceProvider
                .configure({
                    tokenLocation: 'token-custom',
                    apiEndpoints: {
                        base: '/api',
                        login: '/login-custom',
                        tokenExchange: '/token-custom',
                        refresh: '/refresh-custom',
                    }
                });
    
        }

    }

    class LoginController {
    
        static $inject = ['$rootScope', '$mdDialog', '$mdToast', 'ngJwtAuthService', 'deferredCredentials', 'loginSuccess', 'userService'];
        constructor(private $rootScope:global.IRootScope,
                    private $mdDialog:ng.material.IDialogService,
                    private $mdToast:ng.material.IToastService,
                    private ngJwtAuthService:NgJwtAuthService,
                    private deferredCredentials:ng.IDeferred<NgJwtAuth.ICredentials>,
                    private loginSuccess:{promise:ng.IPromise<NgJwtAuth.IUser>},
                    private userService:common.services.user.UserService) {
    
            this.handleLoginSuccessPromise();
    
        }
    
        /**
         * Register the login success promise handler
         */
        private handleLoginSuccessPromise() {
    
            //register error handling and close on success
            this.loginSuccess.promise
                .then(
                    (user) => this.$mdDialog.hide(user), //on success hide the dialog, pass through the returned user object
                    null,
                    (err:Error) => {
                        if (err instanceof NgJwtAuthCredentialsFailedException) {
                            this.$mdToast.show(
                                (<any>this.$mdToast).simple()
                                    .hideDelay(2000)
                                    .position('top')
                                    .content(err.message)
                                    .parent('#loginDialog')
                            );
                        } else {
                            console.error(err);
                        }
                    }
                );
        }
    
        /**
         * allow the user to manually close the dialog
         */
        public cancelLoginDialog() {
            this.ngJwtAuthService.logout(); //make sure the user is logged out
            this.$mdDialog.cancel('closed');
        }
    
        /**
         * Attempt login
         * @param username
         * @param password
         */
        public login(username, password) {
    
            let credentials:ICredentials = {
                username: username,
                password: password,
            };
    
            this.deferredCredentials.notify(credentials); //resolve the deferred credentials with the passed creds
    
        }
    
    }

    angular.module(namespace, [])
        .config(LoginConfig)
        .controller(namespace + '.controller', LoginController);

}
```

## Todo
* Better documentation with examples in typescript.
* Site hosted on github showing off examples with material