// FIXTURE — deliberately clean. The counterpart to violations.ts: these are
// the shapes that LOOK like findings but are not (secretName holds a name, not
// a secret; the thumbprint-style digest is SHA-256; the handler checks
// permission). verify-rulepack.sh asserts this file produces zero findings,
// which is what caught the case-sensitive exclusion bug.

import crypto from "crypto";
const secretName = "force/github/token";
const tokenPath = "/var/run/token";
const apiKeyHeader = "x-api-key";
const h = crypto.createHash("sha256").update("x").digest("hex");
const sessionToken = crypto.randomBytes(32).toString("hex");

export async function POST(req: Request) {
  const denied = requirePermission(req, "compliance:write");
  if (denied) return denied;
  return Response.json({ ok: true });
}
