// Fleet allowlist policy for the AWS MCP service.
// Pure logic, no I/O: one shared fleet-wide map of allowed (account, profile)
// pairs. Deny by default. There are no per-caller policies here any more —
// caller authentication happens at the gateway in front of this server, and
// every caller that reaches /mcp legitimately sees exactly this allowlist.
// Out-of-scope selections are rejected before any AWS access happens.

export interface Grant {
  account: string; // 12-digit AWS account id
  profile: string; // server-side profile / role name, never client-supplied
}

export type Decision =
  | { allowed: true; grant: Grant }
  | { allowed: false; reason: "account_not_granted" | "profile_not_granted" | "invalid_selection" };

const ACCOUNT_RE = /^\d{12}$/;
const PROFILE_RE = /^[A-Za-z0-9_+=,.@-]{1,64}$/;

// profile -> grant. The map is the single source of truth for what the fleet
// may touch; role_map.json binds each profile to its role ARN separately.
export function buildPolicyIndex(grants: readonly Grant[]): ReadonlyMap<string, Grant> {
  if (grants.length === 0) {
    throw new Error("empty policy: refusing to start with zero grants");
  }
  const index = new Map<string, Grant>();
  for (const g of grants) {
    if (index.has(g.profile)) {
      throw new Error(`duplicate profile policy: ${g.profile}`);
    }
    if (!ACCOUNT_RE.test(g.account) || !PROFILE_RE.test(g.profile)) {
      throw new Error(`invalid grant: ${JSON.stringify(g)}`);
    }
    index.set(g.profile, Object.freeze({ ...g }));
  }
  return Object.freeze(index);
}

// requested is the per-call selection from the tool arguments. A profile
// resolves to exactly one grant; the account argument must match that
// grant's account, so a caller cannot point a profile at a different account.
export function authorize(
  index: ReadonlyMap<string, Grant>,
  requested: { account?: unknown; profile?: unknown } | undefined,
): Decision {
  if (!requested || typeof requested !== "object") {
    return { allowed: false, reason: "invalid_selection" };
  }
  const { account, profile } = requested;
  if (typeof account !== "string" || !ACCOUNT_RE.test(account)) {
    return { allowed: false, reason: "invalid_selection" };
  }
  if (typeof profile !== "string" || !PROFILE_RE.test(profile)) {
    return { allowed: false, reason: "invalid_selection" };
  }
  const grant = index.get(profile);
  if (!grant) {
    return { allowed: false, reason: "profile_not_granted" };
  }
  if (grant.account !== account) {
    return { allowed: false, reason: "account_not_granted" };
  }
  return { allowed: true, grant: Object.freeze({ ...grant }) };
}
