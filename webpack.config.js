const path = require("path");
const webpack = require("webpack");

module.exports = {
  mode: "production",
  entry: ["./index.ts"],
  output: {
    path: path.resolve(__dirname, "dist/browser"),
    filename: "vaultysid.min.js",
    libraryTarget: "umd",
    globalObject: "this",
  },
  optimization: {
    minimize: true,
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
      },
    ],
  },
  resolve: {
    extensions: [".ts", ".js"],
    fallback: {
      crypto: require.resolve("crypto-browserify"),
      buffer: require.resolve("buffer/"),
      stream: require.resolve("stream-browserify"),
      vm: require.resolve("vm-browserify"),
      // path: require.resolve("path-browserify"),
      util: require.resolve("util/"),
      assert: require.resolve("assert/"),
    },
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ["buffer", "Buffer"],
      process: "process/browser",
    }),
    new webpack.DefinePlugin({
      "process.env.NODE_DEBUG": false,
    }),
  ],
  devtool: "source-map",
};
