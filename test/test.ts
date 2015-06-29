/// <reference path="../typings/tsd.d.ts" />


var expect = chai.expect;

describe('Service Provider Tests', () => {

  var ngJwtAuthServiceProviderObj;

  describe('Configuration', () => {


    beforeEach(function () {

      angular.module("providers", ['ngJwtAuth']); //require the module as dependency
      module("providers"); //mock the depending module

      module((ngJwtAuthServiceProvider) => {
        ngJwtAuthServiceProviderObj = ngJwtAuthServiceProvider; //register injection of service provider
      });

      inject(); //complete injection
    });


    it('should configure api endpoints', function () {

      ngJwtAuthServiceProviderObj.setApiEndpoints({
        base: 'mock/base/path/',
        login: 'mock/login',
        refresh: 'mock/refresh'
      });

      expect(ngJwtAuthServiceProviderObj.apiEndpoints.base).to.equal('mock/base/path/');
      expect(ngJwtAuthServiceProviderObj.apiEndpoints.login).to.equal('mock/login');
      expect(ngJwtAuthServiceProviderObj.apiEndpoints.refresh).to.equal('mock/refresh');
    });

  });


});
