# syntax=docker/dockerfile:1
FROM node:22-slim AS builder
WORKDIR /app
COPY .npmrc package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY .npmrc package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install --omit=dev && rm -rf /root/.npm
USER node
CMD ["node", "dist/index.js"]
