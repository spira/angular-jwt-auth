require('phantomjs-polyfill');

module.exports = function(config) {
    config.set({

        frameworks: ['chai-as-promised', 'mocha', 'sinon', 'sinon-chai'],

        preprocessors: {
            'dist/**/*.js': ['commonjs', 'coverage']
        },

        files: [
            './node_modules/phantomjs-polyfill/bind-polyfill.js',
            'dist/**/*.js',
            'test/tmp/test/**/*.spec.js'
        ],

        reporters: ['mocha', 'coverage'],

        port: 9018,
        runnerPort: 9100,
        urlRoot: '/',

        autoWatch: false,
        browsers: [
            // 'PhantomJS',
            'Chrome',
        ],

        client: {
            captureConsole: true,
            mocha: {
                bail: true
            }
        },

        logLevel: config.LOG_VERBOSE,

        coverageReporter: {
            // specify a common output directory
            dir: 'reports/coverage',
            reporters: [
                // reporters not supporting the `file` property
                //{type: 'html', subdir: 'report-html'},
                {type: 'lcov', subdir: 'report-lcov'},
                {type: 'clover', subdir: 'app'}
            ]
        }
    });
};
