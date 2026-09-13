<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX QA Report

## Current audit baseline

Audit date: 2026-09-13.

Baseline reviewed: `3a0b456ecceecd826a8c15b596653149b685c95e` on `main`.

That baseline entered this review with passing post-merge Tooling and CodeQL. The current audit branch is `audit/full-code-docs-qa-20260913`; final claims in this file apply only after fresh exact-head gates complete on the final branch SHA.

The detailed review ledger is [`CODE-REVIEW-2026-09-13.md`](CODE-REVIEW-2026-09-13.md).

## Proof states

PARA11AX deliberately separates:

- **repository-proven**: tests/static review ran on one exact Git tree;
- **CI-proven**: required GitHub workflows passed for that exact SHA;
- **deployment-proven**: Vercel reports READY for that exact Git SHA;
- **transport-proven**: the deployed route behaves correctly at HTTP/MCP level;
- **OAuth-proven**: authorization and token exchange succeed;
- **configured**: required runtime secret/wiring is present;
- **vendor-entitled**: the upstream account accepts the requested capability;
- **credential-capability-proven**: an authorized operation actually succeeds;
- **client-connected**: the particular MCP client/session can dispatch a protected call.

These states are not interchangeable. A green generic smoke cannot prove a tier-3 quota provider executed. A configured key cannot prove entitlement. A successful OAuth token exchange followed by no `/mcp` request is not a PARA11AX backend failure.

## Current contract

### Provider fabric

- 39 registered Evidence v2 providers;
- nine workflows: `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, `certificate`;
- `fast`, `standard`, `full` admission profiles;
- 24-provider IP reference workflow;
- large MISP feeds remain tier 3 and outside fast-profile admission;
- provider `active/configured` is not a synonym for live health;
- no universal maliciousness score.

CISA ADP SSVC preserves `Exploitation`, `Automatable`, and `Technical Impact` separately. MODAT Magnify uses the canonical current host and parser contract; because MODAT is tier 3/quota, provider-specific acceptance is required to prove it executed.

### MCP

The public catalog contains 13 tools. OAuth uses authorization-code + S256 PKCE, optional `offline_access`, refresh-token support and AES-256-GCM sealed tokens with purpose-separated key derivation. Legacy HMAC token minting is not re-enabled.

The external MCP edge converts a valid authentication-required result into an HTTP 401 challenge. Swarm and User Scanner advertise strict bounded schemas matching their runtime validators. Registered-command execution remains fail-closed to server-safe catalog entries.

### Evidence and state

Evidence v2 remains authoritative. Intelligence Kernel, Decision Support, Evidence Graph and Guidance are deterministic derived projections, not replacement evidence. Operator surfaces such as User Scanner, Shodan and GreyNoise Swarm remain operator context unless independently promoted through an Evidence v2 path.

Mission, investigation and case state is explicit state-in/state-out for MCP. KQL is validated/projected but not executed. ServiceNow-ready output is generated but not submitted automatically.

### STIX

Stable STIX object IDs derive from normalized stable keys. Do not overstate this as byte-for-byte deterministic bundle identity when a bundle container identifier may be generated independently.

## Findings closed in this audit

### QA-2026-09-13-01 — permissive MCP metadata

**RED:** `test/mcp-schema-hardening.test.js` required runtime-equivalent schema constraints for GreyNoise Swarm and User Scanner and failed against `additionalProperties: true` metadata.

**Fix:** both tools now advertise only supported fields with explicit enums/ranges and `additionalProperties: false`. Runtime validators remain authoritative.

### QA-2026-09-13-02 — provider documentation drift

**RED:** documentation contracts were extended to bind `docs/PROVIDERS.md` to the executable provider count and CISA ADP SSVC semantics.

**Fix:** the canonical provider reference now states 39 providers and documents CISA ADP without collapsing its three SSVC dimensions.

### QA-2026-09-13-03 — stale MCP auth prose

**Fix:** MCP documentation now describes refresh/offline access, sealed AES-256-GCM tokens, external 401 challenge normalization, strict bounded tool schemas and the distinction between successful token exchange and successful protected dispatch.

### QA-2026-09-13-04 — documentation navigation / historical-state ambiguity

**Fix:** the docs index now identifies current operational docs and explicitly treats dated `docs/superpowers/plans/` and `docs/superpowers/specs/` as immutable historical design records rather than current behavior.

## Required exact-head gates

A branch is not QA-complete until fresh evidence exists for the exact final SHA:

```text
Node test suite
MAXX/repository invariants
Maltego tests
Python compilation
ShellCheck
PowerShell syntax
public-release audit
dependency audit
CodeQL JavaScript/TypeScript
CodeQL Python
CodeQL baseline compatibility
documentation contracts
GHAS/new-alert review where available
```

Production acceptance is a later, separate gate after merge/deploy. It should additionally prove the exact merged Git SHA is READY and execute authenticated MCP plus provider-specific diagnostics where the integration is credential/quota/entitlement bound.

## Known external/residual boundaries

The Node `[DEP0169] url.parse()` warning previously observed in production has no app-owned `url.parse(` call and no application dependency tree explaining it; it remains classified as Vercel/Node runtime-wrapper behavior unless a future stack trace proves otherwise.

Cloud/vendor account errors, quotas and entitlements remain upstream/runtime state rather than static-code defects. ChatGPT conversation-local connector disablement can also prevent dispatch before PARA11AX receives a request; production logs are the boundary evidence for distinguishing that from backend authentication failure.

## Historical QA records

Git history preserves earlier QA baselines, deployment IDs and issue-by-issue closure records. This current report intentionally describes the present contract instead of accumulating every obsolete deployment SHA into one immortal document. For implementation history, use Git history and dated review artifacts.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
