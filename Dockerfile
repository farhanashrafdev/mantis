# ──────────────────────────────────────────────────────────────────────────────
# mantis — Multi-stage Docker Build
#
# Stage 1: Build the TypeScript source into JS
# Stage 2: Lean production image with only compiled output
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM node:22-alpine3.21 AS builder

# Upgrade zlib to patched version (fixes CVE-2026-22184, CVE-2024-37175)
RUN apk upgrade --no-cache zlib

WORKDIR /app

# Install dependencies first (layer cache optimisation)
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source and compile
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Prune dev dependencies
RUN npm prune --omit=dev

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM node:22-alpine3.21 AS runtime

# Upgrade zlib to patched version (fixes CVE-2026-22184, CVE-2024-37175)
RUN apk upgrade --no-cache zlib

LABEL org.opencontainers.image.title="mantis" \
      org.opencontainers.image.description="Open-source AI red-team CLI. Automated security testing for LLM apps" \
      org.opencontainers.image.source="https://github.com/farhanashrafdev/mantis" \
      org.opencontainers.image.license="Apache-2.0" \
      org.opencontainers.image.vendor="farhanashrafdev"

ENV NODE_ENV=production

# Run as non-root
RUN addgroup -S mantis && adduser -S mantis -G mantis

WORKDIR /app

# Copy only what we need from the builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Switch to non-root user
USER mantis

ENTRYPOINT ["node", "dist/cli/cli.js"]
