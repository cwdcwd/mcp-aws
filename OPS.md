# mcp-aws operations notes (3gf-10.x)

## Shape
- `src/policy.ts`: one fleet-wide (account, profile) allowlist. Deny by default. No per-caller policy: caller authentication happens at the gateway in front of this server (per-agent LiteLLM gateway keys, same as every other MCP).
- `src/server.ts`: Streamable-HTTP-style JSON-RPC on `node:http`, POST `/mcp`. No bearer-token handling — the endpoint trusts the LAN fence that only lets the gateway host reach it and enforces the fleet allowlist on every call.
- `src/aws.ts`: two-hop role chain via `@aws-sdk/client-sts` + `@aws-sdk/credential-provider-ini`: base key (`mcp-host` profile in `~/.aws`) → AssumeRole `McpAwsHub` (hop 1) → AssumeRole `McpAwsReadOnly` in the grant's account (hop 2) → GetCallerIdentity. Both hops stamp `SourceIdentity` so CloudTrail ties calls to this box. Hub and target sessions are cached separately and refreshed 5 minutes before expiry. Only read-only ops are allowed. The role-map ARN's account segment must match the grant or the call fails closed (`role_map_mismatch`).
- `src/redact.ts`: log redaction for key ids, session tokens, secrets and bearer tokens.
- `src/main.ts`: env-driven entry point (see header comment for variables).

## Dependencies (owner-approved, pinned, save-exact)
- `@modelcontextprotocol/sdk@1.32.2`
- `@aws-sdk/client-sts@3.1165.0`
- `@aws-sdk/credential-provider-ini@3.973.28` (added 2026-11-12 for the profile-chained base credentials; owner-approved as part of the gateway-key rework)
- `zod@4.6.7`

Approved by lazybaer in Slack 2026-11-10. Reverting them would be a policy change.

## Deployment (owner gated)
- Build on devpi06: `docker buildx build --platform linux/arm64 -t mcp-aws:<sha> .` from the merged tree, then update the compose `image:` pin.
- Secrets: the base AWS identity lives in `/home/cwd/.aws/credentials` (`[mcp-host]`, 0600, host secret store, never in the repo). `~/.aws` is mounted read-only into the container. Role ARNs and the fleet allowlist are non-secret config in `runtime/`.
- Roles: `McpAwsHub` and `McpAwsReadOnly` only, read-only scope enforced by IAM + the `READ_ONLY_OPS` set.
- Network fence is mandatory: the port carries no bearer gate any more, so a DOCKER-USER rule must limit :3009 to the gateway host before the ungated image goes live.

## Verification
- `npm test` (`node --test --experimental-strip-types test/`): 32 tests, unit and HTTP integration, all with stub transports. No live AWS calls.
- Live checks after deploy: gateway-key initialize/tools/list/tools/call on hub + one target account; no-auth and foreign-source requests must be rejected by the gateway or the fence respectively.
