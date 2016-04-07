var loaders = require("./loaders");
var webpack = require('webpack');
module.exports = {
    entry: ['./src/ngJwtAuth.ts'],
    output: {
        filename: 'build.js',
        path: 'tmp'
    },
    resolve: {
        root: __dirname,
        extensions: ['', '.ts', '.js', '.json']
    },
    resolveLoader: {
        modulesDirectories: ["node_modules"]
    },
    devtool: "source-map-inline",
    module: {
        loaders: loaders,
        postLoaders: [
            {
                test: /^((?!\.spec\.ts).)*.ts$/,
                exclude: /(node_modules)/,
                loader: 'istanbul-instrumenter'
            }
        ]
    },
    ts: {
        configFileName: 'tsconfig.test.json'
    }
};
