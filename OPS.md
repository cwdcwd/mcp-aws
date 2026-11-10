# mcp-aws operations notes (3gf-10-1, first cut)

## Shape
- `src/policy.ts`: caller -> (account, profile) allowlist. Deny by default.
- `src/server.ts`: Streamable-HTTP-style JSON-RPC on `node:http`, POST `/mcp`, bearer auth. Tokens are stored as sha256 digests and compared timing-safely.
- `src/sts.ts`: AssumeRole through STS with SigV4 signed by `node:crypto`. Role ARN comes from a server-side profile->role map. Credentials are cached per (caller, account, profile), refreshed 5 minutes before expiry, and deduplicated under concurrency.

## Dependencies
None. The earlier commit `e5e6639` added `@aws-sdk/client-sts@3.1165.0`, `@modelcontextprotocol/sdk@1.32.2` and `zod@4.6.7`. Those were reverted because they were not owner-approved (AC 3). If the owner approves them later, record the approval in the bead first.

## Deployment (owner gated, not performed)
- Build: `docker build -t mcp-aws:dev .` on devpi06. Needs owner approval for the base-image pull.
- Secrets: bridge bearer tokens (hashed) and the base AWS identity come from the host secret store, not the repo. Roles are assumed only; the base identity must have sts:AssumeRole on the mapped roles and nothing else.
- Roles: none of the roles in the mapping may be write roles for this cut.

## Verification
- `node --test test/` (Node 26): unit and HTTP integration tests, all using stub transports. No live AWS calls, no network.

## Not yet done
- Production transport (fetch to sts.amazonaws.com) and the `AwsResolver` that runs signed AWS calls are not wired. The server still takes an injected resolver.
- No live HTTP listen entry point in this cut.
- Log redaction is not yet verified by a test.
