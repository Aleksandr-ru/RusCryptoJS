'use strict';

var webpack = require('webpack');
var CleanWebpackPlugin = require('clean-webpack-plugin');
var WebpackCopyAfterBuildPlugin = require('webpack-copy-after-build-plugin');
var path = require('path');
var libraryName = 'RusCryptoJS';
var filename = 'ruscrypto.min.js';

module.exports = (env, argv) => {
    if (argv.mode === 'production') {
        var plugins = [
            new CleanWebpackPlugin([
                './dist'
            ]),
            new WebpackCopyAfterBuildPlugin({
                main: '../docs/js/' + filename
            })
        ];
        var devServer = undefined;
    }
    else {
        var plugins = [
            new webpack.HotModuleReplacementPlugin()
        ];
        var devServer = {
            hot: true,
            publicPath: "/js/",
            contentBase: "./docs",
        };
    }
    return {
        entry: {
            main: [ 'babel-polyfill', './src' ]
        },
        output: {
            path: path.resolve(__dirname, 'dist'),
            filename: filename,
            library: libraryName,
            libraryTarget: 'umd',
            umdNamedDefine: true,
            // https://github.com/webpack/webpack/issues/1625#issuecomment-407553490
            globalObject: "typeof self !== 'undefined' ? self : this"
        },
        resolve: {
            extensions: ['.js'],
        },
        module: {
            rules: [{
                test: /\.js$/, 
                loaders: ['babel-loader'], 
                exclude: /node_modules/
            }],
        },
        plugins: plugins,
        devtool: "source-map",
        devServer: devServer
    }
};