import {NgJwtAuthServiceProvider, NgJwtAuthException} from "./ngJwtAuthServiceProvider";
import {NgJwtAuthService} from "../service/ngJwtAuthService";
import {INgJwtAuthServiceConfig} from "../ngJwtAuthInterfaces";

import "angular";
import "angular-mocks";
import "../ngJwtAuth";

let expect:Chai.ExpectStatic = chai.expect;

let defaultAuthServiceProvider:NgJwtAuthServiceProvider;

describe('Default configuration', function () {

    let defaultAuthService:NgJwtAuthService;

    beforeEach(() => {

        angular.mock.module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
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

    let authServiceProvider:NgJwtAuthServiceProvider;
    let customAuthService:NgJwtAuthService;
    let partialCustomConfig:INgJwtAuthServiceConfig = {
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

        angular.mock.module('ngJwtAuth', (_ngJwtAuthServiceProvider_) => {
            authServiceProvider = _ngJwtAuthServiceProvider_; //register injection of service provider

            authServiceProvider.configure(partialCustomConfig);
        });

    });

    it('should throw an exception when invalid configuration is passed', () => {

        let testInvalidConfigurationFn = () => {
            authServiceProvider.configure(<any>{invalid:'config'});
        };

        expect(testInvalidConfigurationFn).to.throw(NgJwtAuthException);

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