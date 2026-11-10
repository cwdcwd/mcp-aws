# devpi06 is ARM64: build with `docker buildx build --platform linux/arm64 -t mcp-aws .`
# Node 24 runs .ts sources directly via built-in type stripping (no build step).
FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
USER node
EXPOSE 8800
ENTRYPOINT ["node", "src/main.ts"]
