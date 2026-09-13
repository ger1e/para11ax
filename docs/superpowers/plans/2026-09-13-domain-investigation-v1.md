<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md), [docs/DOMAIN-INVESTIGATION.md](https://github.com/ger1e/para11ax/blob/main/docs/DOMAIN-INVESTIGATION.md), and the current README.

# Domain Investigation v1 Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

## Goal

Implement the approved Domain Investigation v1 workflow as a deterministic PARA11AX-native domain investigation artifact that combines canonical passive Evidence v2, existing Webamon evidence, bounded operator-context imports, IOC correlation, conservative blocking guidance, STIX 2.1 export, analyst reporting, shell integration, MCP parity, and next-agent handoff.

## Architecture

Keep authority boundaries explicit. Existing `enrich()` and provider workflows remain the only source of Evidence v2. Domain Investigation consumes a completed domain enrichment and never calls providers itself. Surface/vulnerability inputs are normalized as operator context. A pure core rebuild function deterministically derives IOCs, recommendations, phases, report and handoff after every accepted transition. Shell keeps one volatile artifact in runtime memory; MCP remains stateless and client-carried. STIX is a separate export adapter over the artifact.

## Tech Stack

Node.js 24.x ESM, built-in `node:test`/`assert`, existing PARA11AX Evidence v2 and semantic contracts, existing shell command catalog/shared runtime, existing MCP JSON-RPC server, existing STIX 2.1 utilities, GitHub Actions `Tooling smoke` as the required protected-branch verifier.

## Task 1: Lock the Domain Investigation core contract with failing tests

**Files:**
- Create: `test/domain-investigation.test.js`
- Create later: `src/core/domain-investigation.js`

**Step 1: Write failing core tests**

Cover:
- valid domain Evidence v2 enrichment builds `domain-investigation-v1.0`;
- enrichment target/type mismatch fails closed;
- Webamon presence is projected from existing evidence rather than a second provider path;
- passive relationships produce normalized/deduplicated IOC pivots;
- surface and vulnerability imports are bounded, scalar-only operator context;
- >500 records, >2 MiB import payload, >4096-char fields, nested hostile values and malformed references fail closed;
- import transitions rebuild deterministically without mutating the prior artifact;
- two independent direct-malicious Evidence v2 providers can yield `BLOCK`;
- one direct malicious source plus independent threat context yields `BLOCK_CANDIDATE`;
- exposure/registration/routing/certificate/shared-infrastructure/operator-only context cannot yield `BLOCK`;
- contradictions/insufficient direct evidence downgrade rather than upgrade action;
- report explicitly labels imports as operator context and states PARA11AX did not execute active scanning;
- handoff contains phase state, evidence fingerprints/providers, operator record IDs, unresolved pivots, recommendations, limitations and bounded next actions without raw oversized evidence.

**Step 2: Commit RED tests**

Commit message: `test: define domain investigation v1 contract`

**Step 3: Prove RED in CI**

Open a draft PR from `feat/domain-investigation-v1` to `main`. Confirm `Tooling smoke` fails because `src/core/domain-investigation.js`/required exports do not exist. Record the failing job/step before implementation.

## Task 2: Implement the pure core with minimum authority surface

**Files:**
- Create: `src/core/domain-investigation.js`
- Modify as needed: `src/core/index.js` only if the repository has a core barrel that must expose the feature

**Step 1: Implement validators and canonicalization**

Implement local pure helpers for domain validation, canonical JSON byte sizing, scalar-field normalization, safe HTTP(S) references, record IDs, stable sorting, deep freeze, and Evidence v2 identity validation. No `fetch`, environment access, filesystem, child process, dynamic evaluation or model call.

**Step 2: Implement artifact construction/transitions**

Export:
- `createDomainInvestigation(enrichment)`
- `importDomainSurface(artifact, input)`
- `importDomainVulnerabilities(artifact, input)`
- `rebuildDomainInvestigation(input)` only if useful internally/publicly without widening the contract unnecessarily.

Every transition validates the complete authoritative inputs, returns a new frozen artifact, and rebuilds all derived projections.

**Step 3: Implement IOC projection**

Normalize exact target plus explicit Evidence v2 relationships and approved imported scalar fields into `domain|url|ip|hash|asn|certificate|cve`. Deduplicate by `type:value`, retain provenance entries, source authority and evidence fingerprints.

**Step 4: Implement conservative recommendation engine**

Use Evidence v2 `observation.verdict`, `observation.kind`, `semantics.class`, `semantics.semanticClass`, `semantics.sourceRole`, provider identity, relationships and contradictions. Direct-malicious eligibility must be allowlisted by semantic/directness rules; contextual classes such as network/exposure/certificate/registration and operator imports never count as a direct malicious vote. Emit explicit `ruleId`, direct/context sources, contradictions and reasons.

**Step 5: Implement phases, report and handoff**

Derive phase status from actual supplied data only. Build compact deterministic report data plus rendered text if consistent with existing report patterns. Build a bounded handoff packet using evidence fingerprints/provider names and operator record IDs rather than raw evidence bodies.

**Step 6: Run/observe CI GREEN for core tests**

Push implementation and confirm Domain Investigation core tests pass. Any unexpected failure triggers `superpowers:systematic-debugging` before patching.

**Step 7: Commit**

Commit message: `feat: add domain investigation core`

## Task 3: Add deterministic STIX 2.1 export

**Files:**
- Create: `test/domain-investigation-stix.test.js`
- Create: `src/export/domain-investigation-stix.js`
- Reuse: `src/export/stix.js`

**Step 1: Write RED tests**

Cover deterministic bundle identity/content, supported IOC mappings, CVE vulnerability mapping, safe external references only, imported-only provenance not fabricated, max 100 objects, schema validation, duplicate suppression and stable object ordering.

**Step 2: Prove RED**

Push tests and observe the expected missing-module/export failure.

**Step 3: Implement minimum exporter**

Reuse existing stable STIX identity/validation utilities where compatible. Do not alter canonical gateway STIX semantics. Export only Domain Investigation projections.

**Step 4: Prove GREEN and commit**

Commit message: `feat: export domain investigations as stix`

## Task 4: Add volatile shared-shell workflow

**Files:**
- Create: `test/domain-investigation-command.test.js`
- Modify: `app/shell-core/catalog.js`
- Modify: `src/control/commands.js`
- Modify only if required by existing transport plumbing: `src/control/shell-node-executor.js`
- Modify only if required by exact file/stdin integration: `bin/para11ax.mjs`

**Step 1: Write RED command tests**

Define commands:
- `domain-investigation build <gateway-enrichment-json>`
- `domain-investigation surface-import <surface-json>`
- `domain-investigation vulnerability-import <vulnerability-json>`
- `domain-investigation show`
- `domain-investigation report`
- `domain-investigation stix`
- `domain-investigation handoff`
- `domain-investigation clear`

Assert volatile runtime state, atomic failed transitions, existing `--file`/`--stdin` content transport behavior, disconnect/reboot lifetime consistency, and typed JSON/text outputs.

**Step 2: Prove RED**

Push tests and observe unknown-command/absent-runtime-state failures.

**Step 3: Implement shell adapter**

Add `domainInvestigation: null` to the shared runtime. Route all transformations through pure core functions. Do not add provider execution, arbitrary local scanning or implicit stdin consumption.

**Step 4: Prove GREEN and commit**

Commit message: `feat: expose domain investigation shell workflow`

## Task 5: Add stateless MCP parity

**Files:**
- Create: `test/domain-investigation-mcp.test.js`
- Modify: `src/mcp/server.js`
- Modify if public capability metadata enumerates grouped tools: corresponding MCP/meta contract source

**Step 1: Write RED MCP tests**

Add grouped tool `para11ax_domain_investigation` with explicit `action`:
- `build`
- `surface_import`
- `vulnerability_import`
- `show`
- `report`
- `stix`
- `handoff`

Assert discovery metadata, OAuth/scope behavior inherited from MCP policy, explicit client-carried artifact for stateful transitions, target mismatch rejection, import body bounds, no hidden server persistence, and structured typed output.

**Step 2: Prove RED**

Push and observe missing tool/handler failures.

**Step 3: Implement MCP adapter**

Reuse pure core/export functions. Raise request-body allowance only on the exact grouped tool path/action if existing MCP body parsing permits scoped limits; never broadly raise unrelated endpoints without a contract test.

**Step 4: Prove GREEN and commit**

Commit message: `feat: expose domain investigation through mcp`

## Task 6: Documentation and contract drift protection

**Files:**
- Create: `docs/DOMAIN-INVESTIGATION.md`
- Modify: `README.md`
- Modify: `docs/MCP.md`
- Modify: `docs/SHELL.md`
- Modify: `CHANGELOG.md`
- Modify/add relevant documentation-contract test(s)
- Regenerate/update release/capability manifest only if required by repository verification scripts

**Step 1: Add RED documentation-contract tests where the repository enforces documented counts/names**

If MCP grouped-tool count is asserted, update the expected count from 13 to 14 and require the exact Domain Investigation tool/commands/docs links.

**Step 2: Document semantics and safety boundaries**

Document the five-phase model, Evidence v2 versus operator-context authority, Webamon reuse, explicit local/authorized active scanning boundary, recommendation rules, artifact schema, shell/MCP examples, STIX/report/handoff outputs and hard bounds.

**Step 3: Run drift generators/checks and commit**

Commit message: `docs: document domain investigation workflow`

## Task 7: Full verification, review and integration

**Files:**
- No new feature scope unless verification exposes a defect.

**Step 1: Invoke `superpowers:verification-before-completion`**

Use GitHub Actions evidence, not assumptions. Confirm the latest feature-branch SHA has successful required checks, especially `Tooling smoke`.

**Step 2: Inspect CI details**

Fetch workflow runs/jobs/logs for the latest SHA. Confirm repository verification, tests, shell lint/governance/public-release audit and any CodeQL/security workflow required by the PR complete as expected. Distinguish optional/skipped checks from passing checks.

**Step 3: Invoke `superpowers:requesting-code-review`**

Review the complete diff against the approved spec. Check for authority collapse, arbitrary egress, accidental active scanning, score fabrication, secret leakage, unsafe import handling, state divergence between Shell/MCP, docs drift and untested branches.

**Step 4: Fix review findings with TDD**

For every substantive defect, add/reproduce a failing test first, then patch minimally and reverify.

**Step 5: Mark PR ready and integrate**

Once required checks are green and review has no blocking findings, mark the PR ready. Merge using the repository-supported protected-branch method only after verifying the expected head SHA has not moved.

**Step 6: Final verification**

Fetch merged `main`, confirm the merge commit/status, and report exact implemented surfaces, verification evidence, any intentionally deferred non-goals, and the PR/commit reference.
