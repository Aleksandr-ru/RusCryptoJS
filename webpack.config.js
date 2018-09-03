'use strict';

var webpack = require('webpack');
var CopyWebpackPlugin = require('copy-webpack-plugin');
var path = require('path');
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
        filename: './dist/ruscrypto.min.js',
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
        new webpack.HotModuleReplacementPlugin(),
        new CopyWebpackPlugin([{
            'from': './dist/ruscrypto.min.js',
            'to': path.resolve('./docs/js')
        }])
    ],
    devtool: "source-map",
    devServer: {
        hot: true
    }
};