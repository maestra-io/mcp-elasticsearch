FROM node:22-slim AS builder
WORKDIR /app
ARG GH_PKG_TOKEN
RUN git config --global url."https://x-access-token:${GH_PKG_TOKEN}@github.com/".insteadOf "ssh://git@github.com/"
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
ARG GH_PKG_TOKEN
RUN git config --global url."https://x-access-token:${GH_PKG_TOKEN}@github.com/".insteadOf "ssh://git@github.com/"
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./
RUN npm install --omit=dev && rm -rf /root/.npm && rm -f /root/.gitconfig
USER node
CMD ["node", "dist/index.js"]
