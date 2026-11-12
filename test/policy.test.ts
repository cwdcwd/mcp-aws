import { test } from "node:test";
import assert from "node:assert/strict";
import { authorize, buildPolicyIndex, type Grant } from "../src/policy.ts";

const A = "169011556980";
const B = "477582241276";

const index = buildPolicyIndex([
  { account: A, profile: "mcp-tools" },
  { account: B, profile: "mcp-consulting" },
] satisfies Grant[]);

test("allows the exact granted (account, profile) pair", () => {
  const d = authorize(index, { account: A, profile: "mcp-tools" });
  assert.ok(d.allowed);
  if (d.allowed) {
    assert.equal(d.grant.account, A);
    assert.equal(d.grant.profile, "mcp-tools");
  }
});

test("rejects a profile the fleet map does not carry", () => {
  assert.deepEqual(authorize(index, { account: A, profile: "mcp-hub" }), {
    allowed: false,
    reason: "profile_not_granted",
  });
  assert.deepEqual(authorize(index, { account: A, profile: "admin" }), {
    allowed: false,
    reason: "profile_not_granted",
  });
});

test("rejects an account that does not match the profile's grant", () => {
  // mcp-tools is bound to A: pointing it at any other account must not
  // resolve, even though the profile name itself is valid.
  assert.deepEqual(authorize(index, { account: B, profile: "mcp-tools" }), {
    allowed: false,
    reason: "account_not_granted",
  });
  assert.deepEqual(authorize(index, { account: "333333333333", profile: "mcp-tools" }), {
    allowed: false,
    reason: "account_not_granted",
  });
});

test("rejects an account the fleet map does not carry", () => {
  assert.deepEqual(authorize(index, { account: "333333333333", profile: "mcp-consulting" }), {
    allowed: false,
    reason: "account_not_granted",
  });
});

test("rejects malformed selections before matching", () => {
  for (const bad of [
    { account: "12345", profile: "mcp-tools" },
    { account: "1690115569800", profile: "mcp-tools" },
    { account: "1690-1155-6980", profile: "mcp-tools" },
    { account: A, profile: "" },
    { account: A, profile: "x".repeat(65) },
    { account: A, profile: "a b" },
    { account: undefined, profile: "mcp-tools" },
    { account: A, profile: 42 },
    {},
    undefined,
  ] as { account?: unknown; profile?: unknown }[]) {
    assert.deepEqual(authorize(index, bad), { allowed: false, reason: "invalid_selection" }, JSON.stringify(bad));
  }
});

test("returned grant is a frozen copy, not a mutable reference", () => {
  const d = authorize(index, { account: A, profile: "mcp-tools" });
  assert.equal(d.allowed, true);
  if (d.allowed) {
    assert.throws(() => {
      (d.grant as { profile: string }).profile = "admin";
    }, TypeError);
  }
});

test("buildPolicyIndex rejects duplicate profiles and invalid grants", () => {
  assert.throws(
    () => buildPolicyIndex([{ account: A, profile: "mcp-tools" }, { account: B, profile: "mcp-tools" }]),
    /duplicate/,
  );
  assert.throws(
    () => buildPolicyIndex([{ account: "1690115569800", profile: "mcp-tools" }]),
    /invalid grant/,
  );
  assert.throws(
    () => buildPolicyIndex([{ account: A, profile: "has space" }]),
    /invalid grant/,
  );
});

test("buildPolicyIndex rejects an empty fleet map (fail closed)", () => {
  assert.throws(() => buildPolicyIndex([]), /empty/);
});

test("buildPolicyIndex returns a frozen index", () => {
  assert.ok(Object.isFrozen(index));
});
