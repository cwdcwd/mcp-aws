import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createMcpServer, hashToken, type AwsResolver } from "../src/server.ts";

const A = "111111111111", B = "222222222222";
const calls: string[] = [];
const aws: AwsResolver = {
  async invoke(g, op) { calls.push(`${g.account}/${g.profile}/${op}`); return { ok: true }; },
};
const tokens = new Map([
  [hashToken("tok-alice"), "alice"],
  [hashToken("tok-bob"), "bob"],
]);
const policies = [
  { callerId: "alice", grants: [{ account: A, profile: "readonly" }] },
  { callerId: "bob", grants: [{ account: B, profile: "readonly" }] },
];
const server = createMcpServer({ tokens, policies, aws, maxBodyBytes: 512 });
let base = "";
before(() => new Promise<void>((r) => server.listen(0, "127.0.0.1", () => {
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r();
})));
after(() => new Promise<void>((r) => server.close(() => r())));

const rpc = (token: string | null, body: unknown) => fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const callTool = (token: string | null, args: Record<string, unknown>) =>
  rpc(token, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "aws_invoke", arguments: args } });

test("negative: no bearer token -> 401, nothing invoked", async () => {
  calls.length = 0;
  const r = await callTool(null, { account: A, profile: "readonly", op: "GetCallerIdentity" });
  assert.equal(r.status, 401);
  assert.equal(calls.length, 0);
});

test("negative: unknown bearer token -> 401", async () => {
  const r = await callTool("tok-mallory", { account: A, profile: "readonly", op: "GetCallerIdentity" });
  assert.equal(r.status, 401);
});

test("negative: caller cannot reach another caller's account", async () => {
  calls.length = 0;
  const j = await (await callTool("tok-alice", { account: B, profile: "readonly", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, true);
  assert.match(j.result.content[0].text, /account_not_granted/);
  assert.equal(calls.length, 0);
});

test("negative: ungranted profile is denied", async () => {
  calls.length = 0;
  const j = await (await callTool("tok-alice", { account: A, profile: "admin", op: "GetCallerIdentity" })).json();
  assert.match(j.result.content[0].text, /profile_not_granted/);
  assert.equal(calls.length, 0);
});

test("negative: malformed account is rejected before policy match", async () => {
  const j = await (await callTool("tok-alice", { account: "abc", profile: "readonly", op: "X" })).json();
  assert.match(j.result.content[0].text, /invalid_selection/);
});

test("negative: caller identity in body is ignored", async () => {
  calls.length = 0;
  const j = await (await rpc("tok-alice", { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "aws_invoke", arguments: { account: B, profile: "readonly", op: "X" }, caller: "bob" } })).json();
  assert.equal(j.result.isError, true);
  assert.equal(calls.length, 0);
});

test("negative: invalid op name rejected", async () => {
  calls.length = 0;
  const j = await (await callTool("tok-alice", { account: A, profile: "readonly", op: "Get;rm" })).json();
  assert.equal(j.error.code, -32602);
  assert.equal(calls.length, 0);
});

test("negative: oversized body -> 413", async () => {
  const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { pad: "x".repeat(2000) } });
  const r = await rpc("tok-alice", big);
  assert.equal(r.status, 413);
});

test("negative: malformed JSON -> 400", async () => {
  const r = await rpc("tok-alice", "{not json");
  assert.equal(r.status, 400);
});

test("negative: GET is not allowed", async () => {
  const r = await fetch(`${base}/mcp`, { headers: { authorization: "Bearer tok-alice" } });
  assert.equal(r.status, 405);
});

test("positive: granted call reaches AWS resolver once with server-side grant", async () => {
  calls.length = 0;
  const j = await (await callTool("tok-alice", { account: A, profile: "readonly", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, undefined);
  assert.deepEqual(calls, [`${A}/readonly/GetCallerIdentity`]);
});

test("positive: tools/list advertises the single tool", async () => {
  const j = await (await rpc("tok-bob", { jsonrpc: "2.0", id: 3, method: "tools/list" })).json();
  assert.deepEqual(j.result.tools.map((t: any) => t.name), ["aws_invoke"]);
});
