'use strict';

var webpack = require('webpack');
// var path = require('path');
var libraryName = 'RusCryptoJS';

module.exports = {
    entry: {
        vendor: [
            'babel-polyfill'
        ], 
        main: './src'
    },
    output: {
        path: __dirname,
        filename: './dist/bundle.js',
        library: libraryName,
        libraryTarget: 'umd',
        umdNamedDefine: true
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
    plugins: [
        new webpack.HotModuleReplacementPlugin()
    ],
    devtool: "source-map",
    devServer: {
        hot: true
    }
};