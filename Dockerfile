# Build-only artifact. Not built or pushed as part of 3gf-10-1 (owner gate: base image pull + devpi06 deploy).
# Dependency-free: no npm install step. Node runs the TypeScript sources via strip-only mode.
FROM node:26-slim
WORKDIR /app
ENV NODE_ENV=production
COPY src ./src
COPY test ./test
RUN useradd --system --uid 10001 mcp && chown -R mcp /app
USER mcp
EXPOSE 8787
# Entry point wiring is intentionally not included in this cut; see OPS.md.
CMD ["node", "--test", "test/"]
