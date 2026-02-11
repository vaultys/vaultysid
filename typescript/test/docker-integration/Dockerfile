# ── VaultysID Docker Integration Test Image ──
# Single image used for all roles (agent, broker, denied-*, multi-*)
# The entrypoint script is selected via the ROLE env var or command override.

FROM node:22-alpine

# pnpm
RUN corepack enable && corepack prepare pnpm@10.11.0 --activate

WORKDIR /app

# Copy package manifests first for better layer caching
COPY package.json pnpm-lock.yaml ./

# Install dependencies (production + dev because we need tsx)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY index.ts tsconfig.json ./
COPY src/ ./src/

# Copy integration test scripts
COPY test/docker-integration/ ./test/docker-integration/

# Default env vars (can be overridden in docker-compose)
ENV NODE_ENV=production

# Health-check port (not strictly required, but useful for compose)
EXPOSE 9000 9001 9010 9011 9020 9021

# Default: print usage
CMD ["echo", "Set ROLE env or override command, e.g. tsx test/docker-integration/broker.ts"]
