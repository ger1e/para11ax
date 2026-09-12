<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# Provider Source QA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve source quality without widening PARA11AX's security boundary by removing heavyweight MISP feeds from the fast profile and adding authoritative CISA ADP/SSVC CVE enrichment from the public CVE Services API.

**Architecture:** Preserve the existing fixed-source provider model and all Evidence v2 semantics. Change only provider admission metadata for the two static MISP feeds, then add one single-record, read-only CVE provider against the official CVE Services production host. CISA ADP output remains a separate vulnerability-prioritization observation and must never be merged into KEV, EPSS, CVSS, or a universal score.

**Tech Stack:** Node.js 24 ESM, built-in `node:test`, existing `safeFetch`/`fetchJson` boundary, provider manifest v8.1, GitHub Actions, Vercel.

**Spec:** User-requested provider/source QA on 2026-09-12; current production fast IP returns 9 evidence and 2 failures, while both MISP OSINT adapters permit 32 MB static hash-cache reads. CVE Program documentation confirms public `GET /cve/{id}` access and CISA ADP SSVC enrichment in the official CVE record ADP container.

## Global Constraints

- No new runtime dependency.
- No arbitrary egress; every new request uses one fixed HTTPS host and GET only.
- No credential, secret, token, or state persistence.
- Keep CIRCL and Botvrij MISP sources available in `standard` and `full`; only remove them from `fast`.
- CISA ADP output must preserve Exploitation, Automatable, and Technical Impact as separate fields.
- Existing KEV, EPSS, CVSS, CVE metadata, and decision-support semantics remain separate.
- Every production behavior change is RED -> GREEN before merge.

---

### Task 1: Keep heavyweight MISP feeds out of fast enrichment

**Files:**
- Modify: `test/profiles.test.js`
- Modify: `config/providers.json`

**Interfaces:**
- Consumes: existing `selectProviders()` tier policy and provider manifest metadata.
- Produces: both MISP OSINT providers remain admitted to `standard`/`full` but not `fast`.

- [ ] **Step 1: Write the failing admission regression**

Add a test using the real provider registry and IP workflow which asserts `fast` excludes `misp-circl-osint` and `misp-botvrij-osint`, while `standard` includes both.

- [ ] **Step 2: Verify RED**

Run the targeted profile test and require failure because both providers are currently tier 2 and therefore admitted to `fast`.

- [ ] **Step 3: Implement the minimal metadata fix**

Change only the two MISP provider manifest entries from tier 2 to tier 3. Preserve cost class, parser, hosts, response bounds, workflow membership, evidence semantics, and source order.

- [ ] **Step 4: Verify GREEN**

Run the targeted profile test and existing provider-manifest/profile tests.

### Task 2: Add CISA ADP / SSVC as an authoritative CVE source

**Files:**
- Create: `src/providers/cisa-adp.js`
- Modify: `src/providers/index.js`
- Modify: `src/workflows.js`
- Modify: `config/providers.json`
- Create: `test/cisa-adp-contract.test.js`
- Modify count/source-truth tests and release/docs artifacts that intentionally assert the provider count.

**Interfaces:**
- Consumes: `fetchJson(url, { ...context, maxBytes })`; official `https://cveawg.mitre.org/api/cve/{CVE}` CVE Record v5.x shape.
- Produces: provider `cisa-adp`, type `cve`, observation type `ssvc_assessment`, attributes `{ exploitation, automatable, technicalImpact, ssvcVersion, assessedAt, cisaAdpUpdatedAt, kevCataloged }` where values come only from the CISA ADP container.

- [ ] **Step 1: Write parser/transport RED tests**

Use a frozen CVE Record fixture containing a `CISA ADP Vulnrichment` container. Assert one GET to `cveawg.mitre.org`, exact-CVE path encoding, bounded response handling, extraction of all three SSVC axes, preservation of SSVC version/timestamps, and no promotion of those values into a generic maliciousness score.

- [ ] **Step 2: Write absence/error RED tests**

Assert a valid CVE record without CISA ADP returns `no_result` with null SSVC axes; malformed successful schema fails closed; transport errors remain provider failures; unrelated ADP containers cannot be mistaken for CISA.

- [ ] **Step 3: Verify RED**

Run the new test file and require failure because `src/providers/cisa-adp.js` and provider registration do not exist.

- [ ] **Step 4: Implement the minimal provider**

Fetch exactly one public CVE record from `https://cveawg.mitre.org/api/cve/${encodeURIComponent(input.value)}`. Select only an ADP container whose provider short name is `CISA-ADP` (or the documented CISA ADP org id as a consistency check), then extract the `other.type == "ssvc"` metric and optional `other.type == "kev"` block. Emit `ssvc_assessment`; never replace or synthesize CNA/NVD data.

- [ ] **Step 5: Register and route it**

Add `cisa-adp` to provider exports/`ALL_PROVIDERS`, add one manifest entry using fixed host `cveawg.mitre.org`, GET, no auth, tier 1/free/shareable/authoritative/reference-or-near-real-time semantics, and place it in the CVE workflow adjacent to CISA KEV/EPSS so profile ordering remains deterministic.

- [ ] **Step 6: Verify GREEN**

Run new CISA ADP tests, provider contract/manifest/source-truth/workflow/profile tests, and regenerate deterministic release metadata if required by repository invariants.

### Task 3: Release verification

**Files:**
- No additional production code unless fresh evidence identifies a separate root cause.

**Interfaces:**
- Consumes: exact PR head and protected-main merge.
- Produces: verified provider fabric, exact-SHA deployment, and fresh production MCP smoke.

- [ ] **Step 1: Run full repository gates**

Require `npm run check`, dependency audit, Maltego tests, Python compile, shellcheck, PowerShell parse, CodeQL, and GitHub Advanced Security to pass on the exact PR head.

- [ ] **Step 2: Merge only on green security and tooling checks**

Use expected-head protection and preserve protected-main policy.

- [ ] **Step 3: Verify production**

Require Vercel READY on the exact merge SHA and a fresh authenticated `mode=full` production MCP smoke with 13/13 MCP surfaces. Compare fast-IP failure count against the pre-change baseline of 2; do not claim the MISP hypothesis confirmed unless the live count actually changes as predicted.

---

PΛRΛ11ΛX // PER ASPERA AD ASTRA
