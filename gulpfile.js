/*jslint node: true */ // allow 'require' global
'use strict';

var gulp = require('gulp'),
    concat = require('gulp-concat'),
    del = require('del'),
    util = require('gulp-util'),
    es = require('event-stream'),
    ts = require('gulp-typescript'),
    bump = require('gulp-bump'),
    git = require('gulp-git'),
    filter = require('gulp-filter'),
    tagVersion = require('gulp-tag-version'),
    inquirer = require('inquirer'),
    mocha = require('gulp-mocha'),
    tap = require('gulp-tap'),
    clean = require('gulp-clean'),
    _ = require('lodash');

var tsDefinitions = ['./typings/**/*.d.ts'];
var sources = {
    app: {
        ts: _.union(tsDefinitions, ['./src/**/*.ts'])
    },
    test: {
        ts: _.union(tsDefinitions, ['./test/**/*.ts'])
    }
};

var destinations = {
    app: './dist/',
    tmp: './tmp'
};

var tsProject = ts.createProject({
    declarationFiles: true,
    noExternalResolve: true,
    module: 'commonjs'
});

gulp.task('test', function () {

    var tsStream = gulp.src(sources.test.ts)
        .pipe(ts(tsProject));

    tsStream.js
        .pipe(gulp.dest(destinations.tmp))
        .pipe(mocha({reporter: 'spec'}))
        .pipe(clean()) //delete the created js test files when done with them
    ;
});

gulp.task('js:app', function () {

    var tsStream = gulp.src(sources.app.ts)
        .pipe(ts(tsProject));


    es.merge(
        tsStream.dts.pipe(gulp.dest(destinations.js.app)),
        tsStream.js
            .pipe(concat('main.js'))
            .pipe(gulp.dest(destinations.js.app))
    );
});

// deletes the dist folder for a clean build
gulp.task('clean', function () {
    del(['./dist'], function (err, deletedFiles) {
        if (deletedFiles.length) {
            util.log('Deleted', util.colors.red(deletedFiles.join(' ,')));
        } else {
            util.log(util.colors.yellow('/dist directory empty - nothing to delete'));
        }
    });
});

gulp.task('build', [
    'js:app'
]);

gulp.task('bump', function () {

    var questions = [
        {
            type: 'input',
            name: 'bump',
            message: 'Are you sure you want to bump the patch version? [Y/N]'
        }
    ];

    inquirer.prompt(questions, function (answers) {
        if (answers.bump === 'Y') {

            return gulp.src(['./package.json', './bower.json'])
                .pipe(bump({type: 'patch'}))
                .pipe(gulp.dest('./'))
                .pipe(git.commit('bump patch version'))
                .pipe(filter('package.json'))  // read package.json for the new version
                .pipe(tagVersion());           // create tag

        }
    });
});

// watch scripts, styles, and templates
gulp.task('watch', function () {
    gulp.watch(sources.app.ts, ['js:app']);
});

// default
gulp.task('default', ['build', 'watch']);
