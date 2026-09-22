// SARIF -> the smallest report that can still carry compliance meaning.
//
// This file is the disclosure boundary on the customer's side. Semgrep's SARIF
// is full of exactly what must not leave: artifactLocation.uri is a path in
// their tree, region.startLine is a line number, and snippet.text is the source
// itself. So this does not filter that structure — it never walks it. It reads
// ruleId and level, counts them, and builds a new object from scratch. A field
// Semgrep adds in a later version cannot ride along, because nothing is copied.
//
// Rule -> control mapping deliberately lives on the FORCE side, not here. The
// server has to re-derive it anyway (a report from a customer's runner is
// untrusted input), and keeping it there means a mapping correction ships
// without every customer bumping their pinned action version.
//
// Failing to report is not failing the build. A compliance signal that breaks
// someone's deploy pipeline gets removed from the pipeline, and then there is
// no signal at all.

import { createHmac } from "node:crypto";
import { readFileSync, appendFileSync } from "node:fs";

const SCHEMA_VERSION = 1;
const MAX_RULES = 200; // a report is a summary; an unbounded rule list is a data dump

const sarifPath = process.argv[2];
const { FORCE_URL, FORCE_CONNECTION_ID, FORCE_AUDIT_SECRET, FORCE_SCOPE, GITHUB_REPO_NAME } = process.env;

function out(key, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

/** SARIF level -> our severity vocabulary. Unknown levels become WARNING, not dropped. */
function severityOf(level) {
  switch (String(level || "").toLowerCase()) {
    case "error": return "ERROR";
    case "note":
    case "info": return "INFO";
    default: return "WARNING";
  }
}

/**
 * Build the report. Reads two scalars per result and nothing else — see the
 * header. `counts` is keyed by ruleId+severity so one noisy rule is one row.
 */
function buildReport(sarif) {
  const run = (sarif.runs && sarif.runs[0]) || {};
  const results = Array.isArray(run.results) ? run.results : [];

  const counts = new Map();
  const totals = { ERROR: 0, WARNING: 0, INFO: 0 };

  for (const r of results) {
    const ruleId = typeof r.ruleId === "string" ? r.ruleId : "unknown";
    const severity = severityOf(r.level);
    totals[severity] += 1;
    const key = `${ruleId}\u0000${severity}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  const findings = [...counts.entries()]
    .map(([key, count]) => {
      const [ruleId, severity] = key.split("\u0000");
      return { ruleId, severity, count };
    })
    // Loudest first, so a truncated list keeps what matters.
    .sort((a, b) => (b.severity === "ERROR") - (a.severity === "ERROR") || b.count - a.count)
    .slice(0, MAX_RULES);

  const driver = (run.tool && run.tool.driver) || {};

  return {
    schemaVersion: SCHEMA_VERSION,
    connectionId: FORCE_CONNECTION_ID,
    // Repo NAME only. The owner path would disclose the org structure, and the
    // connection already establishes which org this is.
    repo: GITHUB_REPO_NAME || null,
    scope: FORCE_SCOPE === "full" ? "FULL_TREE" : "CHANGED_FILES",
    event: process.env.GITHUB_EVENT_NAME || null,
    runId: process.env.GITHUB_RUN_ID || null,
    scannedAt: new Date().toISOString(),
    engine: {
      name: typeof driver.name === "string" ? driver.name : "semgrep",
      version: typeof driver.semanticVersion === "string" ? driver.semanticVersion : null,
      rulepack: "force-compliance",
    },
    totals: {
      error: totals.ERROR,
      warning: totals.WARNING,
      info: totals.INFO,
      distinctRules: counts.size,
      truncated: counts.size > MAX_RULES,
    },
    findings,
  };
}

/**
 * Refuse to send a report carrying anything path-shaped or code-shaped.
 *
 * The construction above cannot produce these, which is exactly why this check
 * is worth running: if it ever fires, the builder was changed in a way that
 * reintroduced disclosure, and the right outcome is a loud local failure rather
 * than a quiet one at the server's gate.
 */
const FORBIDDEN_KEYS = new Set([
  "path", "uri", "locations", "region", "snippet", "start_line", "end_line",
  "startLine", "endLine", "commit_sha", "commitSha", "blob_url", "html_url",
  "artifactLocation", "physicalLocation", "secret", "most_recent_instance",
]);

function findForbidden(value, path = "$") {
  const hits = [];
  if (Array.isArray(value)) {
    value.forEach((v, i) => hits.push(...findForbidden(v, `${path}[${i}]`)));
    return hits;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(k)) hits.push(`${path}.${k}`);
      hits.push(...findForbidden(v, `${path}.${k}`));
    }
  }
  return hits;
}

async function main() {
  if (!FORCE_URL || !FORCE_CONNECTION_ID || !FORCE_AUDIT_SECRET) {
    console.log("::warning::FORCE Code Audit is not configured (url, connection-id or audit-secret missing); skipping report.");
    out("error-count", "0");
    out("reported", "false");
    return;
  }

  let sarif;
  try {
    sarif = JSON.parse(readFileSync(sarifPath, "utf8"));
  } catch (e) {
    console.log(`::warning::Could not read Semgrep SARIF (${e.message}); nothing to report.`);
    out("error-count", "0");
    out("reported", "false");
    return;
  }

  const report = buildReport(sarif);
  out("error-count", String(report.totals.error));

  const leaks = findForbidden(report);
  if (leaks.length) {
    console.log(`::error::FORCE Code Audit refused to send a report carrying repository content at ${leaks.join(", ")}. This is a bug in the action; no report was sent.`);
    process.exitCode = 1;
    out("reported", "false");
    return;
  }

  // Sign the exact bytes sent. Re-serialising server-side would reorder keys.
  const body = JSON.stringify(report);
  const signature = "sha256=" + createHmac("sha256", FORCE_AUDIT_SECRET).update(body, "utf8").digest("hex");

  const url = `${FORCE_URL.replace(/\/+$/, "")}/api/ingest/code-audit`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Force-Signature-256": signature,
        "X-Force-Connection-Id": FORCE_CONNECTION_ID,
        "User-Agent": "FORCE-Code-Audit-Action",
      },
      body,
    });
    if (!resp.ok) {
      const detail = await resp.text().catch(() => "");
      console.log(`::warning::FORCE rejected the code-audit report (${resp.status}). ${detail.slice(0, 200)}`);
      out("reported", "false");
      return;
    }
  } catch (e) {
    // Network failure must not break the customer's pipeline — see header.
    console.log(`::warning::Could not reach FORCE to report the code audit (${e.message}).`);
    out("reported", "false");
    return;
  }

  console.log(
    `FORCE Code Audit: ${report.totals.error} error, ${report.totals.warning} warning, ` +
    `${report.totals.info} info across ${report.totals.distinctRules} rule(s) — reported to FORCE. ` +
    `Full detail with file locations is in the force-code-audit-sarif artifact.`
  );
  out("reported", "true");
}

// Exported for the unit suite.
export { buildReport, findForbidden, severityOf };

if (process.argv[1] && process.argv[1].endsWith("summarize.mjs")) {
  await main();
}
