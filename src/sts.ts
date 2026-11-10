// STS AssumeRole path, built on node:crypto + node:https only (no SDK dependency).
// Server-side only: role ARNs come from a server-side profile->role map, never from the request.
// Credentials are short-lived, cached per (caller, account, profile) and never logged.
import { createHash, createHmac } from "node:crypto";
import type { Grant } from "./policy.ts";

export interface TempCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: number; // epoch ms
}

// Injectable transport: production uses fetch to sts.amazonaws.com; tests inject a stub.
export type Transport = (req: { url: string; method: "POST"; headers: Record<string, string>; body: string }) => Promise<{ status: number; body: string }>;

export interface BaseCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

export interface StsOptions {
  base: () => BaseCredentials;         // server-side base identity (never sent to clients)
  roleArnFor: (grant: Grant) => string | undefined; // server-side profile->role map
  transport: Transport;
  now?: () => number;
  refreshSkewMs?: number;              // refresh this long before expiry
  sessionSeconds?: number;
}

const SERVICE = "sts";
const HOST = "sts.amazonaws.com";

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}
function hmac(key: Buffer | string, s: string): Buffer {
  return createHmac("sha256", key).update(s).digest();
}

// AWS Signature Version 4 for a POST with form body.
export function signV4(p: {
  method: string; host: string; path: string; body: string; region: string;
  service: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string;
  amzDate: string; // YYYYMMDDTHHMMSSZ
}): Record<string, string> {
  const dateStamp = p.amzDate.slice(0, 8);
  const payloadHash = sha256Hex(p.body);
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    host: p.host,
    "x-amz-date": p.amzDate,
  };
  if (p.sessionToken) headers["x-amz-security-token"] = p.sessionToken;
  const signedNames = Object.keys(headers).sort();
  const canonicalHeaders = signedNames.map((k) => `${k}:${headers[k].trim()}\n`).join("");
  const signedHeaders = signedNames.join(";");
  const canonicalRequest = [p.method, p.path, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${p.region}/${p.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", p.amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const kDate = hmac(`AWS4${p.secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, p.region);
  const kService = hmac(kRegion, p.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  headers.authorization =
    `AWS4-HMAC-SHA256 Credential=${p.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return headers;
}

function amzDateOf(ms: number): string {
  return new Date(ms).toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function field(xml: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml);
  return m ? m[1] : undefined;
}

export class StsCredentialBroker {
  private readonly cache = new Map<string, TempCredentials>();
  private readonly inflight = new Map<string, Promise<TempCredentials>>();
  private readonly now: () => number;
  private readonly skew: number;
  private readonly sessionSeconds: number;

  private readonly opts: StsOptions;

  constructor(opts: StsOptions) {
    this.opts = opts;
    this.now = opts.now ?? Date.now;
    this.skew = opts.refreshSkewMs ?? 5 * 60_000;
    this.sessionSeconds = opts.sessionSeconds ?? 3600;
  }

  // Key includes caller so one caller can never receive another caller's session.
  async credentialsFor(callerId: string, grant: Grant): Promise<TempCredentials> {
    const key = JSON.stringify([callerId, grant.account, grant.profile]);
    const hit = this.cache.get(key);
    if (hit && hit.expiration - this.now() > this.skew) return hit;
    const pending = this.inflight.get(key);
    if (pending) return pending;
    const p = this.assumeRole(key, grant).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  private async assumeRole(key: string, grant: Grant): Promise<TempCredentials> {
    const roleArn = this.opts.roleArnFor(grant);
    if (!roleArn) throw new Error("no_role_mapping");
    const base = this.opts.base();
    const now = this.now();
    const body = new URLSearchParams({
      Action: "AssumeRole",
      Version: "2011-06-15",
      RoleArn: roleArn,
      RoleSessionName: `mcp-aws-${sha256Hex(key).slice(0, 16)}`,
      DurationSeconds: String(this.sessionSeconds),
    }).toString();
    const headers = signV4({
      method: "POST", host: HOST, path: "/", body, region: base.region, service: SERVICE,
      accessKeyId: base.accessKeyId, secretAccessKey: base.secretAccessKey,
      amzDate: amzDateOf(now),
    });
    const res = await this.opts.transport({ url: `https://${HOST}/`, method: "POST", headers, body });
    if (res.status !== 200) throw new Error(`assume_role_failed:${res.status}`);
    const creds: TempCredentials = {
      accessKeyId: field(res.body, "AccessKeyId") ?? "",
      secretAccessKey: field(res.body, "SecretAccessKey") ?? "",
      sessionToken: field(res.body, "SessionToken") ?? "",
      expiration: Date.parse(field(res.body, "Expiration") ?? "") || now + this.sessionSeconds * 1000,
    };
    if (!creds.accessKeyId || !creds.secretAccessKey || !creds.sessionToken) throw new Error("assume_role_malformed");
    this.cache.set(key, creds);
    return creds;
  }
}
