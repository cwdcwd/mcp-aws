import { test } from "node:test";
import assert from "node:assert/strict";
import { createAwsResolver, READ_ONLY_OPS } from "../src/aws.ts";
import { redact } from "../src/redact.ts";
import type { Grant } from "../src/policy.ts";

const HUB_ARN = "arn:aws:iam::169011556980:role/McpAwsHub";
const TOOLS_ARN = "arn:aws:iam::169011556980:role/McpAwsReadOnly";
const CONSULT_ARN = "arn:aws:iam::477582241276:role/McpAwsReadOnly";
const HOP1 = "hop1", HOP2 = "hop2", FINAL = "final";

const C = {
  tools: { account: "169011556980", profile: "mcp-tools" } as Grant,
  consult: { account: "477582241276", profile: "mcp-consulting" } as Grant,
};

// Fake STS: hop1 AssumeRole (base creds -> hub session), hop2 AssumeRole
// (hub session -> target role), GetCallerIdentity under the final creds.
// Clients are keyed by credential origin so the chain ordering is assertable.
function fakeSts() {
  const events: string[] = [];
  let serial = 0;
  let expiry = Date.now() + 3600_000;
  const client = (origin: string) => ({
    async send(cmd: any) {
      const name = cmd.constructor?.name ?? "";
      if (name === "AssumeRoleCommand") {
        const { RoleArn, SourceIdentity, RoleSessionName, DurationSeconds } = cmd.input;
        events.push(`AssumeRole[${origin}]->${RoleArn}|src=${SourceIdentity}|session=${RoleSessionName}|dur=${DurationSeconds}`);
        if (RoleArn === HUB_ARN && origin === "base") {
          // base creds -> hub session (hop 1)
          serial++;
          return { Credentials: mkCreds(HOP1, serial, expiry) };
        }
        if (origin === HOP1) {
          // hub session -> target role (hop 2); ARN comes from the resolver
          serial++;
          return { Credentials: mkCreds(HOP2, serial, expiry) };
        }
        throw new Error(`unexpected AssumeRole: origin=${origin} arn=${RoleArn}`);
      }
      events.push(`GetCallerIdentity[${origin}]`);
      return {
        Account: origin === FINAL ? "477582241276" : "169011556980",
        Arn: `arn:aws:sts::169011556980:assumed-role/McpAwsReadOnly/session-${serial}`,
        UserId: `AROAxyz:session-${serial}`,
      };
    },
  });
  return {
    events,
    setExpiry(ms: number) { expiry = ms; },
    baseSts: client("base"),
    sessionClient: () => client(HOP1),
    identityClient: () => client(FINAL),
  };
}

function mkCreds(tag: string, n: number, ms: number) {
  return {
    AccessKeyId: "ASIA" + tag.padEnd(16, "T"),
    SecretAccessKey: "x".repeat(40),
    SessionToken: `tok-${tag}-${n}`,
    Expiration: new Date(ms).toISOString(),
  };
}

test("positive: one call performs hop1 -> hub, hop2 -> target, then GetCallerIdentity", async () => {
  const f = fakeSts();
  const r = createAwsResolver({
    region: "us-east-1",
    sourceIdentity: "devpi06",
    hubRoleArn: HUB_ARN,
    roleArnFor: (p: string) => p === "mcp-tools" ? TOOLS_ARN : p === "mcp-consulting" ? CONSULT_ARN : (() => { throw new Error("no_role_mapping"); })(),
    sts: f.baseSts,
    sessionClient: f.sessionClient,
    identityClient: f.identityClient,
    now: () => 1_000_000,
  });
  const out = await r.invoke(C.consult, "GetCallerIdentity", {});
  assert.equal(out.Account, "477582241276");
  assert.equal(f.events[0], `AssumeRole[base]->${HUB_ARN}|src=devpi06|session=mcp-aws-hub-1000000|dur=900`);
  assert.equal(f.events[1], `AssumeRole[hop1]->${CONSULT_ARN}|src=devpi06|session=mcp-aws-mcp-consulting-1000000|dur=900`);
  assert.equal(f.events[2], "GetCallerIdentity[final]");
  assert.equal(f.events.length, 3);
});

test("positive: hub session is cached and reused across target profiles", async () => {
  const f = fakeSts();
  const r = createAwsResolver({
    region: "us-east-1", sourceIdentity: "devpi06", hubRoleArn: HUB_ARN,
    roleArnFor: () => TOOLS_ARN,
    sts: f.baseSts, sessionClient: f.sessionClient, identityClient: f.identityClient,
    now: () => 1_000_000,
  });
  await r.invoke(C.tools, "GetCallerIdentity", {});
  const hubHops = f.events.filter((e) => e.includes(HUB_ARN)).length;
  await r.invoke({ account: "169011556980", profile: "mcp-tools-alt" } as Grant, "GetCallerIdentity", {});
  assert.equal(f.events.filter((e) => e.includes(HUB_ARN)).length, hubHops, "hub hop reused");
});

test("positive: target session cached until refresh window, then re-assumed", async () => {
  const f = fakeSts();
  let t = 1_000_000;
  f.setExpiry(t + 900_000); // target creds expire shortly after the frozen clock
  const r = createAwsResolver({
    region: "us-east-1", sourceIdentity: "devpi06", hubRoleArn: HUB_ARN,
    roleArnFor: () => TOOLS_ARN,
    sts: f.baseSts, sessionClient: f.sessionClient, identityClient: f.identityClient,
    now: () => t, refreshSkewMs: 300_000,
  });
  await r.invoke(C.tools, "GetCallerIdentity", {});
  await r.invoke(C.tools, "GetCallerIdentity", {});
  const hop2 = f.events.filter((e) => e.startsWith(`AssumeRole[hop1]->${TOOLS_ARN}`)).length;
  assert.equal(hop2, 1, "second call reuses cached target session");
  t += 700_000; // now inside the refresh skew window
  f.setExpiry(t + 900_000);
  await r.invoke(C.tools, "GetCallerIdentity", {});
  assert.equal(f.events.filter((e) => e.startsWith(`AssumeRole[hop1]->${TOOLS_ARN}`)).length, 2, "refresh before expiry");
});

test("negative: non-read-only op refused before any STS call", async () => {
  const f = fakeSts();
  const r = createAwsResolver({
    region: "us-east-1", sourceIdentity: "devpi06", hubRoleArn: HUB_ARN,
    roleArnFor: () => TOOLS_ARN,
    sts: f.baseSts, sessionClient: f.sessionClient, identityClient: f.identityClient,
  });
  await assert.rejects(r.invoke(C.tools, "DeleteBucket" as any), /op_not_allowed/);
  assert.deepEqual(f.events.filter((e) => e.startsWith("AssumeRole")), []);
  assert.ok(READ_ONLY_OPS.has("GetCallerIdentity"));
});

test("negative: role ARN whose account does not match the grant fails closed", async () => {
  const f = fakeSts();
  const r = createAwsResolver({
    region: "us-east-1", sourceIdentity: "devpi06", hubRoleArn: HUB_ARN,
    roleArnFor: () => CONSULT_ARN, // wrong ARN for C.tools' account
    sts: f.baseSts, sessionClient: f.sessionClient, identityClient: f.identityClient,
  });
  await assert.rejects(r.invoke(C.tools, "GetCallerIdentity", {}), /role_map_mismatch/);
  assert.deepEqual(f.events, []);
});

test("negative: incomplete AssumeRole credentials fail closed before GetCallerIdentity", async () => {
  const f = fakeSts();
  // break the fake: hub hop returns creds without SecretAccessKey
  const r = createAwsResolver({
    region: "us-east-1", sourceIdentity: "devpi06", hubRoleArn: HUB_ARN,
    roleArnFor: () => TOOLS_ARN,
    sts: { async send() { return { Credentials: { AccessKeyId: "ASIAshort", Expiration: new Date().toISOString() } }; } },
    sessionClient: f.sessionClient, identityClient: f.identityClient,
  });
  await assert.rejects(r.invoke(C.tools, "GetCallerIdentity", {}), /assume_role_incomplete/);
  assert.deepEqual(f.events, []);
});

test("redaction: AWS key ids, session tokens, bearer tokens never survive", () => {
  const key = "ASIA" + "Q".repeat(16);
  const out = redact(`key=${key} SessionToken=abc123 Authorization: Bearer *** secret: hunter2`);
  assert.ok(!out.includes(key));
  assert.ok(!out.includes("abc123"));
  assert.ok(!out.includes("hunter2"));
});
