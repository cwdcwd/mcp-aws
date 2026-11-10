import { test } from "node:test";
import assert from "node:assert/strict";
import { authorize, buildPolicyIndex } from "../src/policy.ts";

const ACCT_A = "111111111111";
const ACCT_B = "222222222222";
const ACCT_C = "333333333333";

const index = buildPolicyIndex([
  { callerId: "doombot", grants: [{ account: ACCT_A, profile: "readonly-a" }] },
  {
    callerId: "kangbot",
    grants: [
      { account: ACCT_A, profile: "readonly-a" },
      { account: ACCT_B, profile: "readonly-b" },
    ],
  },
]);

test("allows an exact granted (account, profile) pair", () => {
  const d = authorize(index, "kangbot", { account: ACCT_B, profile: "readonly-b" });
  assert.equal(d.allowed, true);
});

test("rejects unknown caller before any selection check", () => {
  assert.deepEqual(authorize(index, "mallory", { account: ACCT_A, profile: "readonly-a" }), {
    allowed: false,
    reason: "unknown_caller",
  });
  assert.deepEqual(authorize(index, undefined, { account: ACCT_A, profile: "readonly-a" }), {
    allowed: false,
    reason: "unknown_caller",
  });
});

test("rejects a granted account with an ungranted profile", () => {
  assert.deepEqual(authorize(index, "doombot", { account: ACCT_A, profile: "admin" }), {
    allowed: false,
    reason: "profile_not_granted",
  });
});

test("rejects an account the caller holds no grant for", () => {
  assert.deepEqual(authorize(index, "doombot", { account: ACCT_B, profile: "readonly-b" }), {
    allowed: false,
    reason: "account_not_granted",
  });
  assert.deepEqual(authorize(index, "doombot", { account: ACCT_C, profile: "readonly-a" }), {
    allowed: false,
    reason: "account_not_granted",
  });
});

test("does not let one caller use another caller's grant", () => {
  // doombot holds no grant for ACCT_B, even though kangbot does.
  const d = authorize(index, "doombot", { account: ACCT_B, profile: "readonly-b" });
  assert.equal(d.allowed, false);
});

test("rejects malformed selections before matching", () => {
  for (const bad of [
    { account: "12345", profile: "readonly-a" },
    { account: "1111111111111", profile: "readonly-a" },
    { account: ACCT_A, profile: "" },
    { account: ACCT_A, profile: "x".repeat(65) },
    { account: ACCT_A, profile: "a b" },
    { account: undefined, profile: "readonly-a" },
    { account: ACCT_A, profile: 42 },
  ]) {
    const d = authorize(index, "doombot", bad);
    assert.deepEqual(d, { allowed: false, reason: "invalid_selection" }, JSON.stringify(bad));
  }
});

test("returned grant is a frozen copy, not a mutable reference", () => {
  const d = authorize(index, "doombot", { account: ACCT_A, profile: "readonly-a" });
  assert.equal(d.allowed, true);
  if (d.allowed) {
    assert.throws(() => {
      (d.grant as { profile: string }).profile = "admin";
    }, TypeError);
  }
});

test("buildPolicyIndex rejects duplicate callers and invalid grants", () => {
  assert.throws(
    () =>
      buildPolicyIndex([
        { callerId: "x", grants: [] },
        { callerId: "x", grants: [] },
      ]),
    /duplicate/,
  );
  assert.throws(
    () => buildPolicyIndex([{ callerId: "x", grants: [{ account: "abc", profile: "p" }] }]),
    /invalid grant/,
  );
});
