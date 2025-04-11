const path = require("path");

module.exports = {
  mode: "production",
  target: "node",
  entry: {
    cli: "./src/cli.ts",
  },
  output: {
    path: path.resolve(__dirname, "out"),
    filename: "[name].js",
  },
  resolve: {
    extensions: [".ts", ".js"],
    alias: {
      "@": path.resolve(__dirname),
    },
  },
  optimization: {
    minimize: false,
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
};
