const webpack = require('webpack');
const path = require('path')

module.exports = {
  mode: 'production',
  entry: './index.js',
  devtool: 'source-map',
  target: "node",
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'vaultysid.node.min.js',
    library: 'Vaultys',
    libraryTarget: 'umd'
  },
  optimization: {
    minimize: true,
  }
};