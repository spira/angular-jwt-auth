'use strict';

var webpackConfig = require('./webpack/webpack.test.js');
require('phantomjs-polyfill');
webpackConfig.entry = {};

module.exports = function(config) {
    config.set({

        frameworks: ['mocha', 'chai', 'chai-as-promised', 'sinon-chai'],

        files: [
            './node_modules/phantomjs-polyfill/bind-polyfill.js',
            './src/test.ts'
        ],


        babelPreprocessor: {
            options: {
                presets: ['es2015']
            }
        },

        preprocessors: {
            'src/test.ts': ['webpack'],
            'src/**/!(*.spec)+(.js)': ['coverage']
        },

        webpackMiddleware: {
            stats: {
                chunkModules: false,
                colors: true
            }
        },
        webpack: webpackConfig,


        port: 9018,
        runnerPort: 9100,
        urlRoot: '/',

        singleRun: true,
        autoWatch: false,
        browsers: [
            'PhantomJS',
            // 'Chrome',
        ],

        client: {
            captureConsole: true,
            mocha: {
                // bail: true
            }
        },

        logLevel: config.LOG_INFO,


        reporters: ['mocha', 'coverage'],

        coverageReporter: {
            // specify a common output directory
            dir: 'reports/coverage',
            reporters: [
                // reporters not supporting the `file` property
                //{type: 'html', subdir: 'report-html'},
                {type: 'text'},
                {type: 'lcov', subdir: 'report-lcov'},
                {type: 'clover', subdir: 'app'}
            ]
        }
    });
};
