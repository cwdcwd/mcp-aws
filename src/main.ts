// Entry point. All identity material comes from the environment or a
// server-side file; nothing about the caller is accepted from the request
// body, and callers authenticate at the gateway in front of this server.
//   MCP_AWS_REGION          (required, e.g. us-east-1)
//   MCP_AWS_SOURCE_IDENTITY (required, stamped on both AssumeRole hops)
//   MCP_AWS_BASE_PROFILE    (default "mcp-host"; ~/.aws credentials profile)
//   MCP_AWS_HUB_ROLE        (required; hop-1 role ARN, e.g. McpAwsHub)
//   MCP_AWS_POLICY_FILE     JSON: [{ "account": "123456789012", "profile": "mcp-tools" }]
//   MCP_AWS_ROLE_MAP_FILE   JSON: { "mcp-hub":     "arn:aws:iam::...:role/McpAwsHub",
//                                    "mcp-tools":  "arn:aws:iam::...:role/McpAwsReadOnly" }
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

const roleMap: Record<string, string> = readJson(need("MCP_AWS_ROLE_MAP_FILE"));
const hubRoleArn = need("MCP_AWS_HUB_ROLE");
// The hub role is internal: it must exist in the role map bookkeeping but is
// never selectable from tool calls (that is enforced by the policy file).
if (!Object.values(roleMap).includes(hubRoleArn)) {
  throw new Error("hub role missing from role map");
}

const aws = createAwsResolver({
  region: need("MCP_AWS_REGION"),
  sourceIdentity: need("MCP_AWS_SOURCE_IDENTITY"),
  hubRoleArn,
  baseProfile: process.env.MCP_AWS_BASE_PROFILE ?? "mcp-host",
  roleArnFor: (profile: string) => {
    const arn = roleMap[profile];
    if (!arn) throw new Error("no_role_mapping");
    return arn;
  },
});

const port = Number(process.env.MCP_AWS_PORT ?? 8800);
createMcpServer({ grants: readJson(need("MCP_AWS_POLICY_FILE")), aws }).listen(port, "0.0.0.0", () => {
  log("info", "server.listening", { port });
});
