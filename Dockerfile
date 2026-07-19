# traceglass collector image.
#   docker build -t traceglass .
#   docker run -p 127.0.0.1:4318:4318 -v traceglass-data:/data \
#     -e TRACEGLASS_TOKEN=change-me traceglass
#
# Inside the container the server must bind 0.0.0.0 to be reachable through
# the port mapping; the mandatory TRACEGLASS_TOKEN enforces auth on that bind.
# node:20-slim (glibc) so better-sqlite3 uses its prebuilt binary.

FROM node:20-slim AS build
WORKDIR /app
# Toolchain fallback in case better-sqlite3 must compile from source.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/tsconfig.json packages/core/
COPY packages/sdk/package.json packages/sdk/tsconfig.json packages/sdk/
COPY packages/cli/package.json packages/cli/tsconfig.json packages/cli/
COPY packages/web/package.json packages/web/tsconfig.json packages/web/vite.config.ts packages/web/
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production TRACEGLASS_HOME=/data
# Copy the whole pruned workspace: npm links @traceglass/* as symlinks into
# packages/, so the tree must move together for module resolution to hold.
COPY --from=build /app /app
VOLUME /data
EXPOSE 4318
ENTRYPOINT ["node", "/app/packages/cli/dist/bin.js", "serve", "--host", "0.0.0.0", "--port", "4318"]
