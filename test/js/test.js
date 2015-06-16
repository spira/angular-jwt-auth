/// <reference path="../typings/mocha/mocha.d.ts" />
/// <reference path="../typings/chai/chai.d.ts" />
/**
 * Module dependencies.
 */
var chai = require('chai');
/**
 * Globals
 */
var expect = chai.expect;
/**
 * Unit tests
 */
describe('User Model Unit Tests:', function () {
    describe('2 + 4', function () {
        it('should be 6', function (done) {
            expect(2 + 4).to.equals(6);
            done();
        });
        it('should not be 7', function (done) {
            expect(2 + 4).to.not.equals(7);
            done();
        });
    });
});
