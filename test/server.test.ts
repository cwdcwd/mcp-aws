import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createMcpServer, type AwsResolver } from "../src/server.ts";

const A = "169011556980", B = "477582241276";
const calls: string[] = [];
const aws: AwsResolver = {
  async invoke(g, op) { calls.push(`${g.account}/${g.profile}/${op}`); return { ok: true }; },
};
const grants = [
  { account: A, profile: "mcp-tools" },
  { account: B, profile: "mcp-consulting" },
];
// No tokens option exists any more: authentication happens at the gateway in
// front of this server; this server's own control is the (account, profile)
// fleet allowlist plus the network fence that only lets the gateway reach it.
const server = createMcpServer({ grants, aws, maxBodyBytes: 512 });
let base = "";
before(() => new Promise<void>((r) => server.listen(0, "127.0.0.1", () => {
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r();
})));
after(() => new Promise<void>((r) => server.close(() => r())));

const rpc = (body: unknown) => fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const callTool = (args: Record<string, unknown>) =>
  rpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "aws_invoke", arguments: args } });

test("positive: initialize answers without any credential header", async () => {
  const j = await (await rpc({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} })).json();
  assert.equal(j.result.serverInfo.name, "mcp-aws");
});

test("positive: tools/list advertises the single tool without a credential header", async () => {
  const j = await (await rpc({ jsonrpc: "2.0", id: 3, method: "tools/list" })).json();
  assert.deepEqual(j.result.tools.map((t: any) => t.name), ["aws_invoke"]);
});

test("positive: granted call reaches AWS resolver once", async () => {
  calls.length = 0;
  const j = await (await callTool({ account: A, profile: "mcp-tools", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, undefined);
  assert.deepEqual(calls, [`${A}/mcp-tools/GetCallerIdentity`]);
});

test("negative: account the fleet map does not carry is denied before invocation", async () => {
  calls.length = 0;
  const j = await (await callTool({ account: "999999999999", profile: "mcp-tools", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, true);
  assert.match(j.result.content[0].text, /account_not_granted/);
  assert.equal(calls.length, 0);
});

test("negative: account mismatched to the profile's grant is denied", async () => {
  calls.length = 0;
  const j = await (await callTool({ account: B, profile: "mcp-tools", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, true);
  assert.match(j.result.content[0].text, /account_not_granted/);
  assert.equal(calls.length, 0);
});

test("negative: profile outside the fleet map is denied", async () => {
  calls.length = 0;
  const j = await (await callTool({ account: A, profile: "mcp-hub", op: "GetCallerIdentity" })).json();
  assert.equal(j.result.isError, true);
  assert.match(j.result.content[0].text, /profile_not_granted/);
  assert.equal(calls.length, 0);
});

test("negative: malformed account is rejected before policy match", async () => {
  const j = await (await callTool({ account: "abc", profile: "mcp-tools", op: "X" })).json();
  assert.match(j.result.content[0].text, /invalid_selection/);
});

test("negative: caller identity in body is ignored", async () => {
  calls.length = 0;
  const j = await (await rpc({ jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "aws_invoke", arguments: { account: B, profile: "mcp-tools", op: "X" }, caller: "someone" } })).json();
  assert.equal(j.result.isError, true);
  assert.equal(calls.length, 0);
});

test("negative: invalid op name rejected", async () => {
  calls.length = 0;
  const j = await (await callTool({ account: A, profile: "mcp-tools", op: "Get;rm" })).json();
  assert.equal(j.error.code, -32602);
  assert.equal(calls.length, 0);
});

test("negative: unknown tool name rejected", async () => {
  const j = await (await rpc({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "other" } })).json();
  assert.equal(j.error.code, -32602);
});

test("negative: oversized body -> 413", async () => {
  const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { pad: "x".repeat(2000) } });
  const r = await rpc(big);
  assert.equal(r.status, 413);
});

test("negative: malformed JSON -> 400", async () => {
  const r = await rpc("{not json");
  assert.equal(r.status, 400);
});

test("negative: GET is not allowed", async () => {
  const r = await fetch(`${base}/mcp`);
  assert.equal(r.status, 405);
});

test("negative: other paths are not found", async () => {
  const r = await fetch(`${base}/other`, { method: "POST", body: "{}" });
  assert.equal(r.status, 404);
});

test("notifications/initialized accepted with 202", async () => {
  const r = await rpc({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(r.status, 202);
});

test("unknown method -> -32601", async () => {
  const j = await (await rpc({ jsonrpc: "2.0", id: 5, method: "nope" })).json();
  assert.equal(j.error.code, -32601);
});
