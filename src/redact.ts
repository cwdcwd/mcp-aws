// Log redaction: strips anything that looks like AWS credential material before a
// string reaches a log line. Applied to every log message and error text.
// Ordered: keyed pairs first (keep the key name, drop the value), then bare token shapes.
const KEYED = /((?:SessionToken|SecretAccessKey|secret|token|password)["']?\s*[:=]\s*["']?)[^"'\s,}]+/gi;
const BEARER = /(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi;
const ACCESS_KEY_ID = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const SECRET_SHAPED = /\b[A-Za-z0-9/+=]{40}\b/g;

export function redact(s: string): string {
  return s
    .replace(KEYED, (_m, key: string) => `${key}[REDACTED]`)
    .replace(BEARER, (_m, pre: string) => `${pre}[REDACTED]`)
    .replace(ACCESS_KEY_ID, "[REDACTED]")
    .replace(SECRET_SHAPED, "[REDACTED]");
}

export function log(level: "info" | "warn" | "error", event: string, fields: Record<string, unknown> = {}): void {
  const safe = JSON.parse(redact(JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields })));
  process.stderr.write(JSON.stringify(safe) + "\n");
}
