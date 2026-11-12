// Streamable HTTP-style JSON-RPC MCP endpoint, built on node:http only.
// Caller authentication happens at the gateway in front of this server (the
// same per-agent gateway keys every other MCP uses); this endpoint trusts the
// LAN fence that only lets the gateway reach it and enforces one shared
// fleet-wide (account, profile) allowlist. No bearer token handling here.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { authorize, buildPolicyIndex, type Grant } from "./policy.ts";

export interface AwsResolver {
  // Server-side only: maps an allowed (account, profile) grant to a credential-scoped call.
  invoke(grant: Grant, op: string, args: Record<string, unknown>): Promise<unknown>;
}

export interface ServerOptions {
  grants: readonly Grant[];
  aws: AwsResolver;
  maxBodyBytes?: number;
}

const MAX_BODY = 64 * 1024;
const TOOL = "aws_invoke";

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  // Drain the whole body even when over the limit so the 413 response can be delivered cleanly.
  return new Promise((resolve, reject) => {
    let size = 0;
    let over = false;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) { over = true; return; }
      chunks.push(c);
    });
    req.on("end", () => over ? reject(new Error("body_too_large")) : resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = body === undefined ? "" : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

export function createMcpServer(opts: ServerOptions): Server {
  const index = buildPolicyIndex(opts.grants);
  const limit = opts.maxBodyBytes ?? MAX_BODY;

  return createServer(async (req, res) => {
    if (req.url !== "/mcp") return send(res, 404, { error: "not_found" });
    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });

    let msg: any;
    try {
      msg = JSON.parse(await readBody(req, limit));
    } catch (e) {
      const code = (e as Error).message === "body_too_large" ? 413 : 400;
      return send(res, code, rpcError(null, -32700, code === 413 ? "body too large" : "parse error"));
    }
    if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
      return send(res, 400, rpcError(msg?.id, -32600, "invalid request"));
    }
    const id = msg.id;
    if (msg.method === "notifications/initialized") return send(res, 202, undefined);

    if (msg.method === "initialize") {
      return send(res, 200, { jsonrpc: "2.0", id, result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "mcp-aws", version: "0.2.0" },
      }});
    }
    if (msg.method === "tools/list") {
      return send(res, 200, { jsonrpc: "2.0", id, result: { tools: [{
        name: TOOL,
        description: "Invoke a read-only AWS operation under a fleet-allowed (account, profile). Auth happens at the gateway.",
        inputSchema: { type: "object", required: ["account", "profile", "op"], properties: {
          account: { type: "string", pattern: "^\\d{12}$" },
          profile: { type: "string" },
          op: { type: "string" },
          args: { type: "object" },
        }},
      }]}});
    }
    if (msg.method === "tools/call") {
      const name = msg.params?.name;
      const a = msg.params?.arguments ?? {};
      if (name !== TOOL) return send(res, 200, rpcError(id, -32602, "unknown tool"));
      // Identity from the body is meaningless without the bridge credential:
      // the request body is never trusted to select callers or scopes.
      const decision = authorize(index, { account: a.account, profile: a.profile });
      if (!decision.allowed) {
        return send(res, 200, { jsonrpc: "2.0", id, result: {
          isError: true,
          content: [{ type: "text", text: `denied: ${decision.reason}` }],
        }});
      }
      if (typeof a.op !== "string" || !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(a.op)) {
        return send(res, 200, rpcError(id, -32602, "invalid op"));
      }
      try {
        const out = await opts.aws.invoke(decision.grant, a.op, (a.args && typeof a.args === "object") ? a.args : {});
        return send(res, 200, { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(out) }] } });
      } catch {
        return send(res, 200, { jsonrpc: "2.0", id, result: { isError: true, content: [{ type: "text", text: "upstream error" }] } });
      }
    }
    return send(res, 200, rpcError(id, -32601, "method not found"));
  });
}
