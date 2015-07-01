# Angular JSON Web Token Authentication Module
Angular authentication with JSON Web tokens.

[![Build Status](https://travis-ci.org/spira/angular-jwt-auth.svg?branch=master)](https://travis-ci.org/spira/angular-jwt-auth) 
[![Coverage Status](https://coveralls.io/repos/spira/angular-jwt-auth/badge.svg?branch=master)](https://coveralls.io/r/spira/angular-jwt-auth?branch=master)
[![Dependency Status](https://gemnasium.com/spira/angular-jwt-auth.svg)](https://gemnasium.com/spira/angular-jwt-auth)

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
        .setApiEndpoints({
            base: '/api/auth/jwt',
            login: '/login',
            refresh: '/refresh'
        })
    ;
}])
```

* Inject the `ngJwtAuthService` and use it!

```js
angular.module('app', ['ngJwtAuth'])
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

## Credential Promise Factory
To handle prompting the user for authentication, angular-jwt-auth provides a registration method to allow the application
 to provide a function that returns a promise containing the credentials to attempt to login, then to retry the intercepted
 request with.
 
Example using a modal from [angular-bootstrap's `$modal`](https://angular-ui.github.io/bootstrap/#/modal) :

```js
angular.module('app', ['ngJwtAuth'])
.run(['ngJwtAuthService', '$modal', function(ngJwtAuthService, $modal){
    ngJwtAuthServiceProvider
        .registerCredentialPromiseFactory(function(existingUser){
            
            var credentialsPromise = $modal.open({
                    templateUrl : '/path/to/template.tpl.html',
                    controller: 'LoginModalCtrl',
                    size : 'md'
                }).result;
            };
            
            return credentialsPromise;
            
        })
    ;
}])
.controller('LoginModalCtrl', ['$scope', '$modal', function($scope, $modalInstance){
    $scope.login = function (username, password) {
        //the promise must resolve with the form {username: string, password: string}
        $modalInstance.close({
            username: username,
            password: password
        });
    };
}])

```
