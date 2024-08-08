const webpack = require("webpack");
const path = require("path");

module.exports = {
  mode: "production",
  entry: "./index.ts",
  devtool: "source-map",
  module: {
    rules: [
      {
        test: /\.ts?$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
  output: {
    path: path.resolve(__dirname, "web"),
    filename: "vaultysid.min.js",
    library: "Vaultys",
    libraryTarget: "umd",
  },
  externals: {
    vaultys: "Vaultys",
  },
  resolve: {
    extensions: [".ts", ".js", "..."],
    alias: {
      crypto: "crypto-browserify",
      stream: "stream-browserify",
    },
    fallback: {
      buffer: require.resolve("buffer/"),
    },
  },
  optimization: {
    minimize: true,
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: "process/browser",
    }),
    new webpack.NormalModuleReplacementPlugin(/node:crypto/, (resource) => {
      resource.request = resource.request.replace(/^node:/, "");
    }),
  ],
};
