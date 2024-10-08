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
    path: path.resolve(__dirname, "esm"),
    library: "Vaultys",
    libraryTarget: "commonjs",
  },
  externals: {
    vaultys: "Vaultys",
  },
  resolve: {
    extensions: [".ts", ".js", "..."],
  },
  optimization: {
    minimize: true,
  },
};
