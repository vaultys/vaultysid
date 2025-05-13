const path = require("path");
const webpack = require("webpack");

module.exports = {
  mode: "development",
  entry: ["./test/shims.ts", "./test/challenger_v0.test.ts", "./test/challenger.test.ts", "./test/file.browser_test.ts", "./test/channel.test.ts", "./test/idManager.test.ts", "./test/saltpack.test.ts", "./test/softCredentials.test.ts", "./test/v0toV1.test.ts", "./test/keymanager.test.ts"],
  output: {
    path: path.resolve(__dirname, "test/assets"),
    filename: "test-bundle.js",
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: "ts-loader",
      },
    ],
  },
  resolve: {
    extensions: [".tsx", ".ts", ".js"],
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
