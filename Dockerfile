# Multi-stage build for the offline Signer Tool CLI.
# Prerequisite: `managed/signer-tools` must be compiled first (`npm run compile:tools`).

FROM node:22-slim AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src ./src
COPY managed ./managed
RUN npm run build && npm prune --omit=dev

FROM node:22-slim

WORKDIR /app

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/managed ./managed

RUN mkdir -p /data && chown node:node /data

USER node
WORKDIR /data

ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]

