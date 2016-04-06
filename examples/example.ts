/**
 * This is an example of all the base features of the ngJwtAuth service.
 * @todo A full demo running in github.io would be preferred
 */
import "angular"
import "angular-material"

// import {NgJwtAuthServiceProvider} from "angular-jwt-auth"
import {NgJwtAuthServiceProvider} from "../dist"
import {NgJwtAuthCredentialsFailedException} from "../src/provider/ngJwtAuthServiceProvider";
import {NgJwtAuthService} from "../src/service/ngJwtAuthService";
import {ICredentials} from "../src/ngJwtAuthInterfaces";

class ExampleConfig {

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

class ExampleController {

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

angular.module('example', [
        'ngJwtAuth',
    ])
    .config(ExampleConfig)
    .controller('ExampleController', ExampleController);