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
      'json5'
    ],
    rename: {}
  }),
  gulp = plugins.help(gulpCore),
  _ = require('lodash'),
  path = require('path'),
  bowerJson = require('./bower.json'),
  packageJson = require('./package.json')
;


var tsDefinitions = ['./typings/**/*.d.ts'];
var sources = {
  app: {
    ts: _.union(tsDefinitions, ['./src/**/*.ts'])
  },
  test: {
    ts: _.union(tsDefinitions, ['./test/**/*.ts']),
    dependency: ['./bower_components/']
  }
};

var destinations = {
  app: './dist/',
  tmp: './tmp'
};

var tsProject = plugins.typescript.createProject({
  declarationFiles: true,
  noExternalResolve: true,
  module: 'commonjs'
});

gulp.task('test', function () {

  var tsStream = gulp.src(sources.test.ts)
    .pipe(ts(tsProject));


  var dependencies = plugins.mainBowerFiles({
    includeDev: true,
    paths: {
      bowerDirectory: 'bower_components',
      bowerJson: 'bower.json'
    }
  });

  console.log('files');


  tsStream.js
    .pipe(gulp.dest(destinations.tmp))
    .pipe(plugins.mocha({reporter: 'spec'}))
    .pipe(plugins.clean()) //delete the created js test files when done with them
  ;
});

gulp.task('js:app', function () {

var tsStream = gulp.src(sources.app.ts)
    .pipe(plugins.typescript(tsProject));


  plugins.eventStream.merge(
    tsStream.dts.pipe(gulp.dest(destinations.app)),
    tsStream.js
      .pipe(plugins.concat(path.basename(bowerJson.main)))
      .pipe(gulp.dest(destinations.app))
  );
});

// deletes the dist folder for a clean build
gulp.task('clean', function () {
  plugins.del(['./dist'], function (err, deletedFiles) {
    if (deletedFiles.length) {
      plugins.util.log('Deleted', plugins.util.colors.red(deletedFiles.join(' ,')));
    } else {
      plugins.util.log(plugins.util.colors.yellow('/dist directory empty - nothing to delete'));
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

  plugins.inquirer.prompt(questions, function (answers) {
    if (answers.bump === 'Y') {

      return gulp.src(['./package.json', './bower.json'])
        .pipe(plugins.bump({type: 'patch'}))
        .pipe(gulp.dest('./'))
        .pipe(plugins.git.commit('bump patch version'))
        .pipe(plugins.filter('package.json'))  // read package.json for the new version
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
