# mcp-aws operations notes (3gf-10-1)

## Shape
- `src/policy.ts`: caller -> (account, profile) allowlist. Deny by default.
- `src/server.ts`: Streamable-HTTP-style JSON-RPC on `node:http`, POST `/mcp`, bearer auth. Tokens are stored as sha256 digests and compared timing-safely.
- `src/aws.ts`: per-(account, profile) short-lived role sessions via `@aws-sdk/client-sts` AssumeRole. Role ARN comes from a server-side map. Sessions are cached and refreshed 5 minutes before expiry. Only read-only ops are allowed.
- `src/redact.ts`: log redaction for key ids, session tokens, secrets and bearer tokens.
- `src/main.ts`: env-driven entry point (see header comment for variables).

## Dependencies (owner-approved, pinned, save-exact)
- `@modelcontextprotocol/sdk@1.32.2`
- `@aws-sdk/client-sts@3.1165.0`
- `zod@4.6.7`

Approved by lazybaer in Slack 2026-11-10. Reverting them would be a policy change.

## Deployment (owner gated, not performed)
- Build: `docker buildx build --platform linux/arm64 -t mcp-aws .` on devpi06. Needs owner approval for the base-image pull.
- Secrets: bridge bearer tokens (hashed) and the base AWS identity come from the host secret store, not the repo. Roles are assumed only; the base identity must have sts:AssumeRole on the mapped roles and nothing else.
- Roles: none of the roles in the mapping may be write roles for this cut.

## Verification
- `npm test` (`node --test --experimental-strip-types test/`): 25 tests, unit and HTTP integration, all with stub transports. No live AWS calls.

## Not yet done
- Live LiteLLM header check.
- devpi06 deployment.
