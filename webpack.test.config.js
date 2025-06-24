const path = require("path");
const webpack = require("webpack");

module.exports = {
  mode: "development",
  entry: ["./test/shims.ts", "./test/pqc.test.ts", "./test/pqcManager.web.test.ts", "./test/challenger_v0.test.ts", "./test/challenger.test.ts", "./test/file.browser_test.ts", "./test/channel.test.ts", "./test/idManager.test.ts", "./test/saltpack.test.ts", "./test/softCredentials.test.ts", "./test/v0toV1.test.ts", "./test/keymanager.test.ts", "./test/vectors.test.ts"],
  output: {
    path: path.resolve(__dirname, "test/assets"),
    filename: "test-bundle.js",
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
      vm: false,
      crypto: require.resolve("crypto-browserify"),
      buffer: require.resolve("buffer/"),
      stream: require.resolve("stream-browserify"),
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
