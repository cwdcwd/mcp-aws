import { test } from "node:test";
import assert from "node:assert/strict";
import { StsCredentialBroker, signV4, type Transport } from "../src/sts.ts";
import type { Grant } from "../src/policy.ts";

const BASE = { accessKeyId: "AKIASYNTHETICBASE", secretAccessKey: "synthetic-base-secret", region: "us-east-1" };
const GRANT: Grant = { account: "111111111111", profile: "readonly-a" };
const ROLE = "arn:aws:iam::111111111111:role/synthetic-readonly";

function stsOk(accessKeyId = "ASIASYNTHETIC1", expiration = "2099-01-01T00:00:00Z") {
  return `<AssumeRoleResponse><AssumeRoleResult><Credentials>
<AccessKeyId>${accessKeyId}</AccessKeyId><SecretAccessKey>synthetic-session-secret</SecretAccessKey>
<SessionToken>synthetic-token</SessionToken><Expiration>${expiration}</Expiration>
</Credentials></AssumeRoleResult></AssumeRoleResponse>`;
}

function stubTransport(calls: Array<{ headers: Record<string, string>; body: string }>, status = 200, body = stsOk()): Transport {
  return async (req) => { calls.push({ headers: req.headers, body: req.body }); return { status, body }; };
}

test("negative: unmapped profile never reaches STS", async () => {
  const calls: any[] = [];
  const b = new StsCredentialBroker({ base: () => BASE, roleArnFor: () => undefined, transport: stubTransport(calls) });
  await assert.rejects(b.credentialsFor("alice", GRANT), /no_role_mapping/);
  assert.equal(calls.length, 0);
});

test("negative: STS failure surfaces as error and caches nothing", async () => {
  const calls: any[] = [];
  const b = new StsCredentialBroker({ base: () => BASE, roleArnFor: () => ROLE, transport: stubTransport(calls, 403, "denied") });
  await assert.rejects(b.credentialsFor("alice", GRANT), /assume_role_failed:403/);
  await assert.rejects(b.credentialsFor("alice", GRANT), /assume_role_failed:403/);
  assert.equal(calls.length, 2, "failure is not cached, so a retry hits STS again");
});

test("negative: malformed STS response is rejected", async () => {
  const b = new StsCredentialBroker({ base: () => BASE, roleArnFor: () => ROLE, transport: stubTransport([], 200, "<x/>") });
  await assert.rejects(b.credentialsFor("alice", GRANT), /assume_role_malformed/);
});

test("positive: AssumeRole is signed SigV4 with server-side role ARN and returns temp creds", async () => {
  const calls: any[] = [];
  const b = new StsCredentialBroker({
    base: () => BASE, roleArnFor: (g) => (g.profile === "readonly-a" ? ROLE : undefined),
    transport: stubTransport(calls), now: () => Date.UTC(2026, 10, 10, 12, 0, 0),
  });
  const c = await b.credentialsFor("alice", GRANT);
  assert.equal(c.accessKeyId, "ASIASYNTHETIC1");
  assert.equal(calls.length, 1);
  const params = new URLSearchParams(calls[0].body);
  assert.equal(params.get("Action"), "AssumeRole");
  assert.equal(params.get("RoleArn"), ROLE);
  assert.match(calls[0].headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIASYNTHETICBASE\/20261110\/us-east-1\/sts\/aws4_request/);
  assert.equal(calls[0].headers["x-amz-date"], "20261110T120000Z");
});

test("isolation: cache is keyed by caller, so two callers get separate sessions", async () => {
  const calls: any[] = [];
  let n = 0;
  const t: Transport = async (req) => { calls.push(req); n++; return { status: 200, body: stsOk(`ASIA${n}`) }; };
  const b = new StsCredentialBroker({ base: () => BASE, roleArnFor: () => ROLE, transport: t });
  const a = await b.credentialsFor("alice", GRANT);
  const z = await b.credentialsFor("zed", GRANT);
  assert.notEqual(a.accessKeyId, z.accessKeyId);
  assert.equal(calls.length, 2);
});

test("concurrency: simultaneous requests for the same caller share one AssumeRole", async () => {
  const calls: any[] = [];
  const b = new StsCredentialBroker({ base: () => BASE, roleArnFor: () => ROLE, transport: stubTransport(calls) });
  const [x, y] = await Promise.all([b.credentialsFor("alice", GRANT), b.credentialsFor("alice", GRANT)]);
  assert.equal(calls.length, 1);
  assert.equal(x, y);
});

test("refresh: credentials near expiry are re-assumed", async () => {
  const calls: any[] = [];
  let t = Date.parse("2026-11-10T12:00:00Z");
  const b = new StsCredentialBroker({
    base: () => BASE, roleArnFor: () => ROLE, transport: stubTransport(calls, 200, stsOk("ASIA1", "2026-11-10T12:10:00Z")),
    now: () => t, refreshSkewMs: 5 * 60_000,
  });
  await b.credentialsFor("alice", GRANT);
  t += 6 * 60_000; // within skew of expiry
  await b.credentialsFor("alice", GRANT);
  assert.equal(calls.length, 2);
});

test("signV4: signature changes when the secret or the date changes (known-answer self-check)", () => {
  const base = { method: "POST", host: "sts.amazonaws.com", path: "/", body: "a=b", region: "us-east-1", service: "sts",
    accessKeyId: "AKIASYNTHETIC", secretAccessKey: "s1", amzDate: "20261110T120000Z" };
  const h1 = signV4(base).authorization;
  assert.equal(h1, signV4(base).authorization, "deterministic");
  assert.notEqual(h1, signV4({ ...base, secretAccessKey: "s2" }).authorization);
  assert.notEqual(h1, signV4({ ...base, amzDate: "20261110T120001Z" }).authorization);
});
