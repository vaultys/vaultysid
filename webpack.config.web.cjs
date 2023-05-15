const webpack = require('webpack');
const path = require('path')

module.exports = {
  mode: 'production',
  entry: './index.js',
  devtool: 'source-map',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'vaultysid.min.js',
    library: 'Vaultys',
    libraryTarget: 'umd'
  },
  externals: {
		"vaultys": "Vaultys",
	},
  resolve: {
    alias: {
      crypto: "crypto-browserify",
      stream: "stream-browserify",
    },
    fallback: {
      buffer: require.resolve('buffer/'),
    },
  },
  optimization: {
    minimize: true,
  },
  plugins: [
    new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
        process: 'process/browser'
    }),
  ]
};