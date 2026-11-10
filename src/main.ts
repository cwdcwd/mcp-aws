// Entry point. All identity material comes from the environment or a server-side
// file; nothing about the caller is accepted from the request body.
//   MCP_AWS_PORT            (default 8800)
//   MCP_AWS_REGION          (required)
//   MCP_AWS_TOKENS_FILE     JSON: [{ "callerId": "doombot", "tokenSha256": "<hex>" }]
//   MCP_AWS_POLICY_FILE     JSON: [{ "callerId": "doombot", "grants": [{ "account": "123456789012", "profile": "readonly" }] }]
//   MCP_AWS_ROLE_MAP_FILE   JSON: { "123456789012/readonly": "arn:aws:iam::123456789012:role/mcp-readonly" }
import { readFileSync } from "node:fs";
import { createMcpServer } from "./server.ts";
import { createAwsResolver } from "./aws.ts";
import { log } from "./redact.ts";

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}
const readJson = (path: string) => JSON.parse(readFileSync(path, "utf8"));

const tokenRows: { callerId: string; tokenSha256: string }[] = readJson(need("MCP_AWS_TOKENS_FILE"));
const tokens = new Map(tokenRows.map((r) => [r.tokenSha256, r.callerId]));
const policies = readJson(need("MCP_AWS_POLICY_FILE"));
const roleMap: Record<string, string> = readJson(need("MCP_AWS_ROLE_MAP_FILE"));

const aws = createAwsResolver({
  region: need("MCP_AWS_REGION"),
  roleArnFor: (g) => {
    const arn = roleMap[`${g.account}/${g.profile}`];
    if (!arn) throw new Error("no_role_mapping");
    return arn;
  },
});

const port = Number(process.env.MCP_AWS_PORT ?? 8800);
createMcpServer({ tokens, policies, aws }).listen(port, "0.0.0.0", () => {
  log("info", "server.listening", { port });
});
