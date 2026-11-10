import { test } from "node:test";
import assert from "node:assert/strict";
import { createAwsResolver } from "../src/aws.ts";
import { redact } from "../src/redact.ts";
import type { Grant } from "../src/policy.ts";

const G: Grant = { account: "111111111111", profile: "readonly" };

function fakeSts() {
  const calls: string[] = [];
  let expiry = 0;
  let serial = 0;
  return {
    calls,
    setExpiry(ms: number) { expiry = ms; },
    sts: {
      async send(cmd: any) {
        const name = cmd.constructor?.name ?? "";
        if (name === "AssumeRoleCommand" || cmd.input?.RoleArn) {
          calls.push("AssumeRole");
          serial++;
          return {
            Credentials: {
              AccessKeyId: "ASIA" + "T".repeat(16),
              SecretAccessKey: "x".repeat(40),
              SessionToken: "sess-" + serial,
              Expiration: new Date(expiry).toISOString(),
            },
          };
        }
        calls.push("GetCallerIdentity");
        return { Account: "111111111111", Arn: "arn:aws:sts::111111111111:assumed-role/mcp", UserId: "AROA:mcp" };
      },
    },
  };
}

test("negative: non-read-only op is refused before any STS call", async () => {
  const f = fakeSts();
  const r = createAwsResolver({ region: "us-east-1", roleArnFor: () => "arn:r", sts: f.sts, sessionClient: () => f.sts, now: () => 0 });
  await assert.rejects(r.invoke(G, "DeleteBucket", {}), /op_not_allowed/);
  assert.equal(f.calls.length, 0);
});

test("negative: missing role mapping fails closed", async () => {
  const f = fakeSts();
  f.setExpiry(Date.now() + 3600_000);
  const r = createAwsResolver({ region: "us-east-1", roleArnFor: () => { throw new Error("no_role_mapping"); }, sts: f.sts, sessionClient: () => f.sts });
  await assert.rejects(r.invoke(G, "GetCallerIdentity", {}), /no_role_mapping/);
  assert.equal(f.calls.length, 0);
});

test("positive: session is cached and reused until near expiry, then refreshed", async () => {
  const f = fakeSts();
  let t = 1_000_000;
  f.setExpiry(t + 900_000);
  const r = createAwsResolver({ region: "us-east-1", roleArnFor: () => "arn:r", sts: f.sts, sessionClient: () => f.sts, now: () => t, refreshSkewMs: 300_000 });
  const a = await r.invoke(G, "GetCallerIdentity", {});
  assert.equal(a.Account, "111111111111");
  await r.invoke(G, "GetCallerIdentity", {});
  assert.equal(f.calls.filter((c) => c === "AssumeRole").length, 1, "second call reuses cached session");

  t += 700_000; // inside the 5-minute refresh skew
  f.setExpiry(t + 900_000);
  await r.invoke(G, "GetCallerIdentity", {});
  assert.equal(f.calls.filter((c) => c === "AssumeRole").length, 2, "refresh before expiry");
});

test("positive: sessions are isolated per (account, profile)", async () => {
  const f = fakeSts();
  f.setExpiry(Date.now() + 3600_000);
  const r = createAwsResolver({ region: "us-east-1", roleArnFor: () => "arn:r", sts: f.sts, sessionClient: () => f.sts });
  await r.invoke(G, "GetCallerIdentity", {});
  await r.invoke({ account: "222222222222", profile: "readonly" }, "GetCallerIdentity", {});
  assert.equal(r._cacheSize(), 2);
});

test("redaction: AWS key ids, session tokens, bearer tokens never survive", () => {
  const key = "ASIA" + "Q".repeat(16);
  const out = redact(`key=${key} SessionToken=abc123 Authorization: Bearer tok.en-9 secret: hunter2`);
  assert.ok(!out.includes(key));
  assert.ok(!out.includes("abc123"));
  assert.ok(!out.includes("tok.en-9"));
  assert.ok(!out.includes("hunter2"));
});
