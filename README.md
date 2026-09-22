# FORCE Code Audit

Compliance-mapped static analysis that runs **in your own CI runner**. Findings
are reported to FORCE as evidence; your source code never leaves your
infrastructure.

## Why it works this way

The FORCE GitHub collector cannot read your source, by construction — the
GitHub App is installed without the Contents permission, so GitHub itself
refuses to serve us a blob, tarball or diff. That guarantee is the point, and
auditing your code was not going to be done by weakening it.

So the analysis runs where the code already is. Semgrep executes on your
runner, against a checkout you already trust it with. What leaves your boundary
is a count-level summary:

| Sent to FORCE | Never sent |
|---|---|
| Rule ids (e.g. `force.tls.verification-disabled`) | File paths |
| Severity and count per rule | Line numbers |
| Repository **name** | Source snippets |
| Scan scope, timestamp, engine version | Commit SHAs, branch names, URLs |

Your developers get the full detail — paths, lines, snippets — as a SARIF
artifact attached to the workflow run, in your repository, where the fixing
happens.

The action checks its own output before sending, and FORCE re-checks it on
arrival. The second check is the real one: a report from your runner is
untrusted input, and FORCE derives the control mappings itself rather than
believing what a report claims about its own compliance meaning.

## Setup

1. In FORCE, open your GitHub connection and choose **Enable code audit**. You
   are shown a signing secret **once**.
2. In GitHub, add it as an Actions secret named `FORCE_AUDIT_SECRET`
   (repository or organization scope).
3. Add the workflow below.

```yaml
# .github/workflows/force-code-audit.yml
name: FORCE Code Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          # Needed only for pull_request runs, so Semgrep can find the merge base.
          fetch-depth: 0

      - uses: BigOnePlatforms/force-code-audit@v1
        with:
          force-url: https://gov.bigforceone.com
          connection-id: gh-1781744119198
          audit-secret: ${{ secrets.FORCE_AUDIT_SECRET }}
          # "changed" scans the PR diff; "full" scans the whole tree.
          scope: changed
```

## Inputs

| Input | Required | Default | Meaning |
|---|---|---|---|
| `force-url` | yes | — | Your FORCE base URL |
| `connection-id` | yes | — | The GitHub connection this repo reports under |
| `audit-secret` | yes | — | Signing secret; pass from `secrets`, never inline |
| `scope` | no | `changed` | `changed` = PR diff, `full` = whole tree |
| `extra-config` | no | — | Extra Semgrep config, e.g. `p/security-audit` |
| `fail-on-error` | no | `false` | Fail the job on ERROR findings |

## What gets checked

The bundled rulepack targets patterns an assessor asks about directly — the
ones where a finding maps cleanly onto a control your SSP has to answer for:
committed credentials, non-FIPS hash algorithms, disabled TLS verification,
non-cryptographic randomness used for tokens, shell and SQL injection,
credential-shaped values in logs, commercial AWS endpoints referenced from
CUI-handling code, route handlers with no visible authorization check, and
inline suppression of security lint rules.

Point `extra-config` at a broader ruleset for general SAST coverage. Findings
from rules FORCE does not recognise are still recorded — mapped to secure
development and flaw remediation only, which is the honest floor for a rule
whose meaning we cannot verify.

## Failure behaviour

A FORCE outage, a bad URL or a missing secret produces a **warning annotation,
not a failed job**. A compliance signal that breaks a deploy pipeline gets
removed from the pipeline, and then there is no signal at all. Use
`fail-on-error: true` when you want findings themselves to block a merge — that
is a separate decision from whether reporting succeeded.

## Severity

`ERROR` is reserved for findings that evidence a control **failing** — a
committed credential, certificate verification switched off. Anything merely
worth a look is `WARNING`. A rulepack that cries wolf at ERROR gets
`fail-on-error` switched off, and then the rules that should stop a merge no
longer do.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Semgrep is installed at runtime
from PyPI and licensed separately by Semgrep, Inc.; it is not redistributed
here.
