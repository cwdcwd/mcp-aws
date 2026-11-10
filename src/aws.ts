// Server-side AWS resolver: maps an already-authorized (account, profile) grant to
// short-lived STS credentials and runs a read-only, allowlisted operation.
// Credentials are cached per (account, profile) and refreshed before expiry.
// Credential values never leave this module and are never logged.
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import type { AwsResolver } from "./server.ts";
import type { Grant } from "./policy.ts";
import { log } from "./redact.ts";

// Read-only operations only. Anything else is refused before any AWS call.
export const READ_ONLY_OPS: ReadonlySet<string> = new Set(["GetCallerIdentity"]);

export interface StsLike {
  send(cmd: unknown): Promise<any>;
}

export interface AwsResolverOptions {
  region: string;
  roleArnFor: (grant: Grant) => string;        // server-side mapping; never client-supplied
  sts?: StsLike;                                // injectable for tests
  sessionClient?: (creds: { accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: Date }) => StsLike;
  now?: () => number;
  refreshSkewMs?: number;                       // refresh this long before expiry
  durationSeconds?: number;                     // short-lived role session
}

interface Cached {
  client: StsLike;
  expiresAt: number;
}

export function createAwsResolver(opts: AwsResolverOptions): AwsResolver & { _cacheSize(): number } {
  const now = opts.now ?? Date.now;
  const skew = opts.refreshSkewMs ?? 5 * 60_000;
  const duration = opts.durationSeconds ?? 900;
  const cache = new Map<string, Cached>();
  const baseSts: StsLike = opts.sts ?? new STSClient({ region: opts.region });

  async function sessionFor(grant: Grant): Promise<StsLike> {
    const key = `${grant.account}\u0000${grant.profile}`;
    const hit = cache.get(key);
    if (hit && hit.expiresAt - now() > skew) return hit.client;

    const roleArn = opts.roleArnFor(grant);
    const out = await baseSts.send(new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: `mcp-aws-${Date.now()}`,
      DurationSeconds: duration,
    }));
    const c = out?.Credentials;
    if (!c?.AccessKeyId || !c?.SecretAccessKey || !c?.SessionToken || !c?.Expiration) {
      throw new Error("assume_role_incomplete");
    }
    const creds = {
      accessKeyId: c.AccessKeyId,
      secretAccessKey: c.SecretAccessKey,
      sessionToken: c.SessionToken,
      expiration: new Date(c.Expiration),
    };
    const client = opts.sessionClient
      ? opts.sessionClient(creds)
      : new STSClient({ region: opts.region, credentials: creds });
    cache.set(key, { client, expiresAt: new Date(c.Expiration).getTime() });
    log("info", "aws.session.refreshed", { account: grant.account, profile: grant.profile, expiresAt: c.Expiration });
    return client;
  }

  return {
    async invoke(grant, op) {
      if (!READ_ONLY_OPS.has(op)) {
        log("warn", "aws.op.refused", { op, reason: "not_read_only" });
        throw new Error("op_not_allowed");
      }
      const client = await sessionFor(grant);
      const out = await client.send(new GetCallerIdentityCommand({}));
      // Return only non-secret identity fields.
      return { Account: out.Account, Arn: out.Arn, UserId: out.UserId };
    },
    _cacheSize: () => cache.size,
  };
}
