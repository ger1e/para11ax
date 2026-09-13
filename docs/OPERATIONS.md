<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Operations

## Proof states

Keep these separate:

1. **Repository-proven** — exact source SHA passes local/repository tests and invariants.
2. **CI-proven** — required GitHub Actions checks pass for that exact SHA.
3. **Configured** — required runtime environment exists.
4. **Deployment-proven** — Vercel reports the expected exact Git SHA and `READY`.
5. **Live-public-proven** — public routes return expected status/content from that deployment.
6. **OAuth-proven** — authorization/token exchange succeeds.
7. **Credential-capability-proven** — a protected call actually succeeds for the relevant provider/worker/entitlement.
8. **MCP-client-connected** — that specific client/session successfully dispatches a protected tool.

Do not compress these into one “production verified” claim.

## Current repository baseline

The 2026-09-13 full audit started from clean `main` SHA:

```text
3a0b456ecceecd826a8c15b596653149b685c95e
```

That baseline had passing post-merge Tooling and CodeQL. The audit work lives on `audit/full-code-docs-qa-20260913`; use [`QA-REPORT.md`](QA-REPORT.md) and [`CODE-REVIEW-2026-09-13.md`](CODE-REVIEW-2026-09-13.md) for exact audit evidence. Do not promote the branch SHA to a production claim until it is merged, deployed and accepted.

## Repository verification

From a clean checkout of the exact candidate SHA:

```text
npm run check
```

The hosted release-quality gate additionally covers the complete Node suite, MAXX/repository invariants, public-release/dependency audits, Maltego tests, Python compilation, ShellCheck, PowerShell syntax and CodeQL JavaScript/TypeScript + Python + compatibility analysis. Documentation contracts are executable tests and therefore part of the branch acceptance surface.

Never weaken a failing invariant merely to make CI green. Fix the behavior or the stale source-of-truth.

## Deployment acceptance

A merge is not production acceptance.

Acceptance sequence:

```text
exact main SHA green in CI
  -> Vercel deployment source SHA matches exact main SHA
  -> deployment READY
  -> public transport smoke
  -> OAuth metadata / token flow where applicable
  -> authenticated MCP smoke
  -> provider/worker-specific diagnostics for credentialed or entitlement-bound integrations
```

For MCP, verify at least:

```text
GET /mcp -> 405 + Allow: POST
initialize/server discovery
13 tools in tools/list
auth challenge for unauthenticated protected call
authenticated para11ax_capabilities call
sequential protected calls without namespace/session collapse
selected enrichment/batch/provider surface
mission/investigation/case/report lifecycle smoke
registered-command boundary
```

A successful OAuth `POST /oauth/token` proves token issuance only. If a client then produces no `/mcp` request, debug the client/session binding before changing PARA11AX auth code.

## MCP authentication operations

The current OAuth bridge uses authorization-code + S256 PKCE with `para11ax:use` and optional `offline_access`. Refresh tokens are supported when offline access is granted. Access/refresh material is AES-256-GCM sealed with purpose separation and bounded lifetime. The obsolete HMAC token format must not be resurrected as a convenience bridge.

At the canonical external edge, a valid MCP authentication-required result becomes HTTP `401` with `WWW-Authenticate`. Invalid/oversized/control-character challenges are not reflected.

## Provider operations

The executable registry currently contains 39 Evidence v2 providers. `active` means registered/configured, not healthy.

Use the following vocabulary in acceptance records:

```text
implemented
configured
eligible
executed
no_result
failed
skipped
production-verified
```

`fast`, `standard`, and `full` control admission. The fast profile intentionally omits large/tier-3 sources such as the CIRCL and Botvrij MISP feeds. Generic fast-profile success therefore does not prove a tier-3 provider ran.

When validating a particular paid/quota provider, use a provider-specific bounded call and record only the provider, operation, status/error class and exact source/deployment SHA. Do not log secrets or arbitrary upstream payloads.

### MODAT

MODAT Magnify uses `api.magnify.modat.io` and is tier 3/quota. Production acceptance must execute a MODAT-specific provider call if the claim is “MODAT works”; a generic enrichment smoke is insufficient.

### GreyNoise Project Swarm

The GreyNoise enrichment adapter and GreyNoise Project Swarm operator utility are separate surfaces. A configured `GREYNOISE_API_KEY` does not prove Sensors/Swarm entitlement. Validate the exact scope/operation required.

GreyNoise Swarm supports `search`, `get`, `unique`, `timeseries`, `diff`, and explicit single-session `export`. Arbitrary destinations/fields and bulk export remain outside the surface.

### User Scanner

Reference path:

```text
Web / MCP
  -> bounded User Scanner handler
  -> configured isolated worker
```

The hosted worker URL is configured through `PARA11AX_USER_SCANNER_URL`; the production alias is `https://user-scanner-kappa.vercel.app`. Optional static service authentication uses `PARA11AX_USER_SCANNER_TOKEN`; trusted Vercel workload identity remains the preferred deployment path where configured. Never log or expose the token value.

The handler accepts `email|username`, bounded category/module selectors and boolean controls. Normalized `found` counts only exact matches; ambiguous upstream hits remain `unverified`. Worker authentication may use the configured static token or trusted workload identity according to deployment configuration.

### Shodan

The native analyst surface is bounded to `shodan host`, `shodan search`, `shodan count`, `shodan stats`, `shodan domain`, and `shodan info`. It is separate from the Evidence v2 provider adapter. Search/domain credit behavior is operational account state, not a static-code guarantee.

## Provider scheduling

Provider Value Scheduler v1.0 only orders already-admitted providers. It does not change workflow/profile membership or broaden egress.

IP reference invariants:

- 24-provider IP workflow;
- max two attempts/provider (48-call ceiling);
- max provider concurrency 4;
- 20-second request deadline;
- deterministic fallback for missing/malformed scheduler metadata;
- no evidence-dependent source suppression;
- no LLM/adaptive runtime ranking.

## Intelligence and evidence operations

Evidence v2 remains authoritative. Intelligence Kernel, Decision Support, Evidence Graph and Guidance are derived deterministic projections. Provider failures/skips affect coverage, not maliciousness. Absence is not benignness. Infrastructure proximity is not attribution.

STIX object IDs are deterministic from stable normalized keys; do not promise byte-identical bundles when a bundle container ID may differ.

## Documentation maintenance

Current operational/project docs are living contracts. Dated `docs/superpowers/plans/` and `docs/superpowers/specs/` are historical records and stay immutable.

When executable source-of-truth changes, update the relevant current docs and drift tests in the same PR. Machine-check facts such as provider count, workflows, route inventory and key protocol semantics where practical.

## Runtime-owned warnings

The previously observed Node `[DEP0169] url.parse()` warning has no app-owned `url.parse(` call and no application dependency tree explaining it. Treat it as Vercel/Node wrapper/runtime-owned unless a future stack trace attributes it to PARA11AX code. Do not perform random application rewrites to cosmetically erase an external warning.

## Release rule

Evidence before assertion:

```text
branch tests green != merged
merged != deployed
deployed != authenticated capability proven
configured != entitled
HTTP 200 != complete evidence
```

The exact SHA is the thread connecting every accepted claim.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
