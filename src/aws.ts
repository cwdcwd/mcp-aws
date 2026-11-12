// Server-side AWS resolver: maps an already-authorized (account, profile)
// grant to a two-hop role chain and runs a read-only, allowlisted operation.
//
//   base access key (mcp-host profile in ~/.aws) --AssumeRole--> McpAwsHub
//   hub session --AssumeRole--> McpAwsReadOnly in the grant's account
//   final session --> GetCallerIdentity
//
// Both hops are stamped with SourceIdentity so CloudTrail ties every call to
// this box. The base key never leaves this module; hub and target sessions
// are cached separately and refreshed before expiry. Nothing is logged.
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { fromIni } from "@aws-sdk/credential-provider-ini";
import type { AwsResolver } from "./server.ts";
import type { Grant } from "./policy.ts";
import { log } from "./redact.ts";

// Read-only operations only. Anything else is refused before any AWS call.
export const READ_ONLY_OPS: ReadonlySet<string> = new Set(["GetCallerIdentity"]);

export interface StsLike {
  send(cmd: unknown): Promise<any>;
}

interface SessionCreds {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
}

export interface AwsResolverOptions {
  region: string;
  sourceIdentity: string;                       // stamped on every AssumeRole ("devpi06")
  hubRoleArn: string;                           // hop-1 role ARN, server-side config
  roleArnFor: (profile: string) => string;      // profile -> target role ARN, server-side config
  baseProfile?: string;                         // ~/.aws credentials profile for the base key (default "mcp-host")
  sts?: StsLike;                                // injectable for tests: hop-1 client over base creds
  sessionClient?: (creds: SessionCreds) => StsLike;  // injectable: client over hop-1 creds (issues hop 2)
  identityClient?: (creds: SessionCreds) => StsLike; // injectable: client over hop-2 creds (identity call)
  now?: () => number;
  refreshSkewMs?: number;
  durationSeconds?: number;
}

interface Cached {
  client: StsLike;
  expiresAt: number;
}

function arnAccount(arn: string): string | undefined {
  // arn:aws:iam::<account>:role/<name>
  if (!/^arn:aws:iam::\d{12}:role\//.test(arn)) return undefined;
  return arn.split(":")[4];
}

function validCreds(c: any): SessionCreds | undefined {
  if (!c?.AccessKeyId || !c?.SecretAccessKey || !c?.SessionToken || !c?.Expiration) return undefined;
  return {
    accessKeyId: c.AccessKeyId,
    secretAccessKey: c.SecretAccessKey,
    sessionToken: c.SessionToken,
    expiration: new Date(c.Expiration),
  };
}

export function createAwsResolver(opts: AwsResolverOptions): AwsResolver & { _cacheSize(): number } {
  const now = opts.now ?? Date.now;
  const skew = opts.refreshSkewMs ?? 5 * 60_000;
  const duration = opts.durationSeconds ?? 900;
  const cache = new Map<string, Cached>();
  const baseSts: StsLike = opts.sts
    ?? new STSClient({ region: opts.region, credentials: fromIni({ profile: opts.baseProfile ?? "mcp-host" }) });

  function sessionName(profile: string): string {
    // RoleSessionName is capped at 64 chars by STS.
    return `mcp-aws-${profile.slice(0, 40)}-${now()}`;
  }

  async function assume(client: StsLike, roleArn: string, name: string): Promise<SessionCreds> {
    const out = await client.send(new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: name,
      SourceIdentity: opts.sourceIdentity,
      DurationSeconds: duration,
    }));
    const creds = validCreds(out?.Credentials);
    if (!creds) throw new Error("assume_role_incomplete");
    return creds;
  }

  // Hop 1: base key -> McpAwsHub. Cached once; refreshed before expiry.
  async function hubClient(): Promise<StsLike> {
    const key = "__hub__";
    const hit = cache.get(key);
    if (hit && hit.expiresAt - now() > skew) return hit.client;
    const creds = await assume(baseSts, opts.hubRoleArn, `mcp-aws-hub-${now()}`);
    log("info", "aws.hop1.refreshed", { role: opts.hubRoleArn.split(":role/")[1], expiresAt: creds.expiration.toISOString() });
    const client = opts.sessionClient
      ? opts.sessionClient(creds)
      : new STSClient({ region: opts.region, credentials: creds });
    cache.set(key, { client, expiresAt: creds.expiration.getTime() });
    return client;
  }

  // Hop 2: hub session -> McpAwsReadOnly in the grant's account.
  async function sessionFor(profile: string): Promise<StsLike> {
    const hit = cache.get(profile);
    if (hit && hit.expiresAt - now() > skew) return hit.client;
    const roleArn = opts.roleArnFor(profile);
    const hub = await hubClient();
    const creds = await assume(hub, roleArn, sessionName(profile));
    log("info", "aws.session.refreshed", { profile, expiresAt: creds.expiration.toISOString() });
    const client = opts.identityClient
      ? opts.identityClient(creds)
      : new STSClient({ region: opts.region, credentials: creds });
    cache.set(profile, { client, expiresAt: creds.expiration.getTime() });
    return client;
  }

  return {
    async invoke(grant: Grant, op: string) {
      if (!READ_ONLY_OPS.has(op)) {
        log("warn", "aws.op.refused", { op, reason: "not_read_only" });
        throw new Error("op_not_allowed");
      }
      const roleArn = opts.roleArnFor(grant.profile);
      // Defense in depth: the role map must agree with the grant's account so
      // a role-map typo can never send a session to the wrong account.
      if (arnAccount(roleArn) !== grant.account) {
        log("warn", "aws.invoke.refused", { reason: "role_map_mismatch", account: grant.account, profile: grant.profile });
        throw new Error("role_map_mismatch");
      }
      const client = await sessionFor(grant.profile);
      const out = await client.send(new GetCallerIdentityCommand({}));
      // Return only non-secret identity fields.
      return { Account: out.Account, Arn: out.Arn, UserId: out.UserId };
    },
    _cacheSize: () => cache.size,
  };
}
