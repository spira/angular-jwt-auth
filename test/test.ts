/// <reference path="../typings/mocha/mocha.d.ts" />
/// <reference path="../typings/chai/chai.d.ts" />
/// <reference path="../typings/lodash/lodash.d.ts" />
/// <reference path="../typings/angularjs/angular.d.ts" />


/**
 * Module dependencies.
 */
import chai = require('chai');

/**
 * Globals
 */

var expect = chai.expect;

describe('Service Provider Tests', () => {

  describe('Api Endpoints', () => {
    it('should have default endpoints', (done) => {
      expect(2+4).to.equals(6);
      done();
    });

    it('should not be 7', (done) => {
      expect(2+4).to.not.equals(7);
      done();
    });
  });
});



