// Caller-scoped authorization policy for the AWS MCP service.
// Pure logic, no I/O: authenticated caller -> allowed (account, profile) pairs.
// Deny by default. Unknown callers and out-of-scope selections are rejected
// before any AWS access happens.

export interface Grant {
  account: string; // 12-digit AWS account id
  profile: string; // server-side profile / role name, never client-supplied
}

export interface CallerPolicy {
  callerId: string; // derived from the authenticated bridge credential, never from the request body
  grants: readonly Grant[];
}

export type Decision =
  | { allowed: true; grant: Grant }
  | { allowed: false; reason: "unknown_caller" | "account_not_granted" | "profile_not_granted" | "invalid_selection" };

const ACCOUNT_RE = /^\d{12}$/;
const PROFILE_RE = /^[A-Za-z0-9_+=,.@-]{1,64}$/;

export function buildPolicyIndex(policies: readonly CallerPolicy[]): Map<string, readonly Grant[]> {
  const index = new Map<string, readonly Grant[]>();
  for (const p of policies) {
    if (index.has(p.callerId)) {
      throw new Error(`duplicate caller policy: ${p.callerId}`);
    }
    for (const g of p.grants) {
      if (!ACCOUNT_RE.test(g.account) || !PROFILE_RE.test(g.profile)) {
        throw new Error(`invalid grant for caller ${p.callerId}`);
      }
    }
    index.set(p.callerId, Object.freeze(p.grants.map((g) => Object.freeze({ ...g }))));
  }
  return index;
}

// authenticatedCaller must come from the verified bridge credential.
// requested is the per-call selection from the tool arguments.
export function authorize(
  index: ReadonlyMap<string, readonly Grant[]>,
  authenticatedCaller: string | undefined,
  requested: { account?: unknown; profile?: unknown },
): Decision {
  if (!authenticatedCaller || !index.has(authenticatedCaller)) {
    return { allowed: false, reason: "unknown_caller" };
  }
  const { account, profile } = requested;
  if (typeof account !== "string" || !ACCOUNT_RE.test(account)) {
    return { allowed: false, reason: "invalid_selection" };
  }
  if (typeof profile !== "string" || !PROFILE_RE.test(profile)) {
    return { allowed: false, reason: "invalid_selection" };
  }
  const grants = index.get(authenticatedCaller)!;
  const accountGrants = grants.filter((g) => g.account === account);
  if (accountGrants.length === 0) {
    return { allowed: false, reason: "account_not_granted" };
  }
  const exact = accountGrants.find((g) => g.profile === profile);
  if (!exact) {
    return { allowed: false, reason: "profile_not_granted" };
  }
  return { allowed: true, grant: exact };
}
