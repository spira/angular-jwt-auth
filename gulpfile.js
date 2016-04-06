/*jslint node: true */ // allow 'require' global
'use strict';

var gulpCore = require('gulp'),
    gulpLoadPlugins = require('gulp-load-plugins'),
    plugins = gulpLoadPlugins({
        pattern: [
            'gulp-*',
            'gulp.*',
            'event-stream',
            'del',
            'globby',
            'inquirer',
            'main-bower-files',
            'minimatch',
            'run-sequence',
            'json5',
            'merge2'
        ],
        rename: {}
    }),
    gulp = plugins.help(gulpCore),
    _ = require('lodash'),
    path = require('path')
;


var tsDefinitions = './typings/browser/**/*.d.ts';
var sources = {
    app: {
        ts: [tsDefinitions, './src/**/*.ts', '!**/*.spec.ts', '!src/test.ts']
    }
};

var destinations = {
    app: './dist',
    coverage: 'reports/**/lcov.info'
};


gulp.task('typescript', function () {

    var tsProject = plugins.typescript.createProject('tsconfig.build.json', {
        declarationFiles: true,
        noExternalResolve: true
    });

    var tsStream = gulp.src(sources.app.ts)
        .pipe(plugins.sourcemaps.init())
        .pipe(plugins.typescript(tsProject, undefined, plugins.typescript.reporter.longReporter()));

    return plugins.merge2([
        tsStream.dts
            .pipe(gulp.dest(destinations.app)),

        tsStream.js
            .pipe(plugins.sourcemaps.write('./', {includeContent: false, sourceRoot: '../src/'}))
            .pipe(gulp.dest(destinations.app))
    ]);

});

// deletes the dist folder for a clean build
gulp.task('clean', function () {
    return plugins.del([destinations.app], function (err, deletedFiles) {
        if (deletedFiles.length) {
            plugins.util.log('Deleted', plugins.util.colors.red(deletedFiles.join(' ,')));
        } else {
            plugins.util.log(plugins.util.colors.yellow('/dist directory empty - nothing to delete'));
        }
    });
});

gulp.task('build', [
    'clean',
    'typescript'
]);

gulp.task('bump', function (cb) {

    var questions = [
        {
            type: 'list',
            message: 'What type of release is this?',
            name: 'bumpType',
            choices: [
                {
                    name: 'Patch (minor fix, no breaking changes)',
                    value: 'patch'
                },
                {
                    name: 'Minor (minor improvement, extended functionality, no breaking changes)',
                    value: 'minor'
                },
                {
                    name: 'Major (Breaking Changes)',
                    value: 'major'
                }
            ]
        },
        {
            type: 'confirm',
            name: 'confirm',
            message: function (answers) {
                return 'Are you sure you want to bump the ' + answers.bumpType + ' version?'
            }
        }

    ];

    plugins.inquirer.prompt(questions, function (answers) {

        if (answers.confirm === true) {

            return gulp.src(['./package.json', './bower.json'])
                .pipe(plugins.bump({type: answers.bumpType}))
                .pipe(gulp.dest('./'))
                .pipe(plugins.git.commit('chore(semver): bump ' + answers.bumpType + ' version'))
                .pipe(plugins.filter('package.json'))  // read package.json for the new version
                .pipe(plugins.tagVersion())           // create tag
                ;
        }
    });
});


// default
gulp.task('default', ['build']);

gulp.task('coveralls', 'submits code coverage to coveralls', [], function () {
    gulp.src(destinations.coverage)
        .pipe(plugins.coveralls());
});
