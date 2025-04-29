import path from "path";
import { dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  reactStrictMode: true,
  experimental: {
    esmExternals: "loose",
  },
  webpack(config) {
    config.resolve.alias["@vaultys/id"] = path.resolve(__dirname, "node_modules/@vaultys/id");
    return config;
  },
};

export default nextConfig;
