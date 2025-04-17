/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  webpack(config) {
    config.resolve.alias["@vaultys/id"] = path.resolve(__dirname, "./node_modules/@vaultys/id");
    return config;
  },
};

export default nextConfig;
