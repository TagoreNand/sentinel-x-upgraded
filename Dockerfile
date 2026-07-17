# syntax=docker/dockerfile:1
# Multi-stage build. Why it matters here:
# - The old single-stage image shipped the full source tree, devDependencies,
#   and the pnpm store to production — a bigger attack surface and a slower
#   pull on every scale-up event.
# - It also ran `npm install` against a pnpm lockfile (non-reproducible) and
#   ran the app as root.

# ---- Stage 1: full dependency install (dev deps needed to build) ----------
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
COPY patches ./patches
# --frozen-lockfile: the lockfile IS the build contract; drift fails the build
# instead of silently shipping different dependency versions than CI tested.
RUN pnpm install --frozen-lockfile

# ---- Stage 2: build client bundle + server bundle -------------------------
FROM deps AS build
COPY . .
RUN pnpm run build

# ---- Stage 3: production-only dependencies --------------------------------
# The server bundle externalizes packages (esbuild --packages=external), so
# runtime node_modules are required — but only `dependencies`, never dev.
FROM node:22-alpine AS prod-deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
COPY patches ./patches
RUN pnpm install --prod --frozen-lockfile

# ---- Stage 4: minimal runtime ----------------------------------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Dedicated non-root user: a compromised app process must not own the container.
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
USER sentinel
EXPOSE 3000
# Container-level liveness for non-K8s runtimes (compose, plain docker).
# Kubernetes uses the /healthz + /readyz probes in the manifest instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "dist/index.js"]
