<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX full code review — 2026-09-13

## Scope

Baseline: `3a0b456ecceecd826a8c15b596653149b685c95e` (`main`). The baseline had passing post-merge Tooling and CodeQL. This audit covers the executable provider/data path, bounded egress and fetch controls, MCP/OAuth/control-plane surface, agentic state workflows, operator utilities, tests, GitHub Actions/release gates, and current project documentation.

Dated files under `docs/superpowers/plans/` and `docs/superpowers/specs/` are historical design records. They were reviewed for context but are intentionally immutable; rewriting history to match current code would make them worse documentation, not better documentation.

## Audit method

1. Freeze review against an exact clean `main` SHA.
2. Review runtime boundaries before presentation layers.
3. Reproduce concrete defects with RED tests.
4. Apply the minimum behavior change required for GREEN.
5. Synchronize current docs only after executable behavior is stable.
6. Run exact-head Tooling, static/security analysis and repository invariants.
7. Review the final diff and preserve unresolved upstream/runtime limitations explicitly.

## Findings and disposition

### MCP tool schema drift — fixed

`para11ax_swarm` and `para11ax_user_scan` had strong runtime validators but advertised permissive MCP schemas with `additionalProperties: true` and only a subset of their real arguments. That made tool discovery weaker than runtime enforcement and encouraged clients to invent unsupported fields.

The MCP catalog now advertises bounded schemas matching the existing runtime contracts. Swarm exposes its supported fields, enums and numeric limits; User Scanner exposes its six supported fields and input bounds. Both use `additionalProperties: false`. Existing runtime validation remains the final enforcement layer.

TDD evidence: `test/mcp-schema-hardening.test.js` was committed first and failed on the permissive schemas before the server schema repair.

### Provider documentation drift — fixed

The provider fabric had advanced to 39 sources after CISA ADP SSVC was added, while the canonical provider document still stated 38 in multiple places. `test/documentation-contracts.test.mjs` now binds the provider document to the executable registry count and requires the CISA ADP SSVC semantics to remain documented.

CISA ADP remains a distinct authoritative decision-support source. `Exploitation`, `Automatable`, and `Technical Impact` are preserved independently rather than collapsed into CVSS, EPSS, KEV or a universal score.

### MODAT Magnify contract — verified from preceding fix

The current adapter uses `api.magnify.modat.io`. The preceding TDD repair aligned parsing with current Magnify fields including `ports[]`, `asn.org`, `geo.country_iso_code`, DNS record-specific value fields and source timestamps. MODAT remains tier 3/quota; a generic fast-profile pass does not prove MODAT executed.

### Provider profile discipline — verified

The fast profile no longer admits the two large MISP feeds merely because of their former tier. Both MISP feeds are tier 3 and remain available to broader profiles. Fast-profile production smoke previously reached 8 evidence / 0 provider failures after the ThreatMiner follow-up repair.

### OAuth / MCP authentication — verified architecture

OAuth uses authorization-code + PKCE and advertises `offline_access` / refresh-token support. Current token sealing uses AES-256-GCM with purpose-separated authenticated encryption and scrypt-derived key material. The canonical external MCP edge converts a valid result-level authentication challenge into HTTP 401 + `WWW-Authenticate` while preserving the internal MCP result model. Legacy pre-refresh sessions cannot be silently upgraded because they never received a refresh token.

The deprecated pre-hardening HMAC token format was not re-enabled.

### Registered command boundary — verified

Remote command execution is registry-driven and fail-closed. Explicit denied command IDs/namespaces, local-admin, filesystem and other unsafe host capabilities remain outside MCP. Unknown command IDs do not gain a generic host-shell fallback.

### User Scanner confidence — verified conservative normalization

The scanner does not trust upstream `found` blindly. It retains upstream count as `rawFound`, promotes only exact target evidence to normalized `found`, and marks ambiguous results `unverified`. Worker URL, input fields, authentication, timeout and response size remain bounded.

### STIX determinism — clarified

STIX object IDs are deterministic from stable normalized keys. The bundle container ID itself may be generated independently. Documentation must avoid claiming byte-for-byte bundle identity when the real guarantee is deterministic object identity/projection behavior.

### Batch semantics — reviewed

Per-item batch state preserves `ok`, `partial` and `error`. The batch response does not manufacture a global benign/success verdict over nested partials. Consumers must inspect item state and enrichment limitations rather than treating HTTP success as evidence completeness.

### Runtime deprecation warning — classified external

The observed Node `[DEP0169] url.parse()` warning has no app-owned `url.parse(` call and the package carries no runtime dependency tree that explains it. It is classified as Vercel/Node wrapper/runtime-owned unless a future stack trace proves otherwise. Rewriting PARA11AX application code to silence an external warning would be fake remediation.

Follow-up (2026-09-16): Vercel later attributed the cold-start warning to its lazy request-query helper and fixed it in `@vercel/node` 5.7.15 (`f7b5377`). PARA11AX now bypasses that legacy helper by parsing `req.url` directly with WHATWG `URL`; behavioral regression tests fail if a Vercel-facing request reads `req.query`.

## Security invariants reviewed

- fixed-host/protocol/method egress policies;
- bounded request and response sizes;
- timeouts and conservative upstream error mapping;
- server-side credential handling and no secret evidence fields;
- no arbitrary provider selection through normal enrichment profiles;
- source-role / freshness / distribution provenance preserved;
- absence and upstream failure not converted into negative evidence;
- no universal maliciousness score;
- MCP discovery separated from protected execution;
- explicit portable mission/investigation/case state rather than hidden remote sessions;
- registered-only remote command execution;
- binary/export boundaries remain explicit rather than silently promoted to evidence.

## Documentation policy

Current operational/project documentation is maintained as a living contract. Machine-checkable facts such as provider count, workflow names and public routes should be asserted in tests where practical. Historical dated plans/specifications are not rewritten after implementation; they remain design-history artifacts.

## Verification gates

A release-quality audit head is not considered complete until the exact source SHA has fresh passing evidence for:

- complete Node test suite;
- MAXX/repository invariants;
- Maltego tests and Python compilation;
- ShellCheck;
- PowerShell syntax validation;
- dependency/public-release audits;
- CodeQL JavaScript/TypeScript;
- CodeQL Python;
- CodeQL baseline compatibility;
- documentation contracts;
- GHAS/new-alert review where available.

Production acceptance remains separate from branch CI. Deployment readiness must prove the exact merged Git SHA, then exercise authenticated production MCP and relevant provider-specific diagnostics rather than assuming a generic smoke proves every quota/credential-bound integration.

## Residual / external proof boundaries

Repository QA cannot prove every third-party entitlement, account quota, network condition, Vercel runtime implementation detail, or ChatGPT conversation-local connector state. In particular, “configured” is not “runtime healthy”, generic fast-profile success is not proof a tier-3 provider executed, and a successful OAuth token exchange is distinct from a client actually dispatching a protected `/mcp` call.

These distinctions are intentional. PARA11AX should report what it can prove, not what would make the dashboard prettier.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
