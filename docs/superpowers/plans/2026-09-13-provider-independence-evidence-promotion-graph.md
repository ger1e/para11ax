<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->

# Provider Independence, Evidence Promotion, and Evidence Graph Implementation Plan

> **For Gergő:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent false provider quorum, add analyst-controlled promotion of operator findings, and project both into the existing deterministic Evidence Graph without creating a second authority model.

**Architecture:** Evidence v2 remains provider authority. A bounded provider-independence resolver maps providers to known upstream families and marks unknown lineage as non-quorum. Domain Investigation recommendations consume unique known quorum-eligible families plus analyst attestations as a separate authority class. Promotion candidates are deterministic derived state; analyst decisions are append-only events; effective attestations are derived from those events. The existing Evidence Graph remains a deterministic projection and explanation layer only.

**Tech Stack:** Node.js ESM, `node:test`, existing PARA11AX Domain Investigation core, Investigation model, Evidence Graph, Shell runtime, MCP server, GitHub Actions CI.

## Non-negotiable invariants

- Unknown or missing provider lineage never counts as an independent BLOCK vote.
- `provider:<name>` may exist only as a display/provenance bucket with `quorumEligible=false`.
- Analyst-promoted evidence never increments provider-family quorum.
- No operator artifact becomes canonical evidence without explicit analyst approval.
- Promotion/revocation history is append-only and deterministic.
- Evidence Graph is derived output, never accepted as authority input.
- Existing Evidence v2 and graph callers remain valid where semantics allow additive compatibility.
- No network access, scanning, arbitrary fetch, shell execution, or secret-bearing references are introduced.
- Shell stays volatile and MCP stays stateless/client-carried.

## Task 1: Provider-independence resolver

**Files:**
- Create: `src/core/provider-independence.js`
- Create: `test/provider-independence.test.js`

### Step 1: Write failing resolver tests

Cover:
- known provider resolves to configured `independenceGroup` and `quorumEligible=true`;
- two providers mapped to one upstream family collapse to one quorum group;
- two known providers in different families remain two quorum groups;
- missing provider metadata resolves to `provider:<name>` only for provenance and `quorumEligible=false`;
- two unknown providers produce zero quorum-eligible groups;
- one known plus one unknown produces one quorum-eligible group;
- invalid confidence/basis/group/reference metadata fails closed;
- output is deterministic regardless of input order.

### Step 2: Run focused test and confirm RED

Run:

```bash
node --test test/provider-independence.test.js
```

Expected: fail because resolver module/functions do not yet exist.

### Step 3: Implement the minimum resolver

Export a small deterministic API, preferably:

```js
createProviderIndependenceRegistry(entries = [])
resolveProviderIndependence(provider, registry)
summarizeProviderIndependence(providersOrEvidence, registry)
```

Normalize and bound provider/group strings, confidence, basis, references, and timestamps. Unknown providers receive a stable display bucket but are explicitly non-quorum.

### Step 4: Re-run focused test and confirm GREEN

```bash
node --test test/provider-independence.test.js
```

### Step 5: Commit

```bash
git add src/core/provider-independence.js test/provider-independence.test.js
git commit -m "feat: add provider independence resolver"
```

## Task 2: Make Domain Investigation quorum source-family aware

**Files:**
- Modify: `src/core/domain-investigation.js`
- Modify: `test/domain-investigation.test.js`

### Step 1: Add failing recommendation regressions

Add exact regression cases:
- three malicious providers in one known family = one vote, never BLOCK;
- two malicious providers in two known families = BLOCK when existing contradiction policy permits;
- two malicious unknown-lineage providers != BLOCK;
- one known malicious family plus one unknown-lineage malicious provider != BLOCK;
- wrapper/vendor mirror mapped to same upstream family does not create false independence;
- recommendation output exposes raw provider count, quorum-eligible group count, exact groups, unknown providers, and registry/version metadata.

### Step 2: Run focused Domain Investigation tests and confirm RED

```bash
node --test test/domain-investigation.test.js
```

Expected: current provider-count logic violates at least same-family/unknown-lineage cases.

### Step 3: Integrate the resolver minimally

Replace provider-name vote counting with unique known `quorumEligible=true` `independenceGroup` counting. Preserve existing top-level recommendation fields where possible and add an explicit `independence` explanation object.

Old Evidence v2 without independence metadata remains readable but contributes zero BLOCK quorum until resolved by the registry.

### Step 4: Re-run tests and confirm GREEN

```bash
node --test test/domain-investigation.test.js test/provider-independence.test.js
```

### Step 5: Commit

```bash
git add src/core/domain-investigation.js test/domain-investigation.test.js
git commit -m "feat: enforce source-family recommendation quorum"
```

## Task 3: Add deterministic evidence-promotion core

**Files:**
- Create: `src/core/evidence-promotion.js`
- Create: `test/evidence-promotion.test.js`

### Step 1: Write failing lifecycle tests

Cover:
- eligible bounded operator artifact creates one deterministic promotion candidate;
- candidate ordering/fingerprint is invariant to input ordering;
- candidate has zero authority before approval;
- approval creates an immutable analyst attestation preserving artifact ID, observable, source, references, actor label, reason, approval time, fingerprint, and authority class;
- rejection creates audit state but no authority;
- revoked attestation is excluded from effective attestations while audit remains;
- supersession keeps prior record/fingerprint historical and activates the newer attestation;
- duplicate active promotion for same source observable/claim is rejected;
- recursive promotion is rejected;
- malformed, oversized, secret-bearing, credential-bearing, or unsafe references fail closed;
- invalid operation is atomic.

### Step 2: Run focused test and confirm RED

```bash
node --test test/evidence-promotion.test.js
```

### Step 3: Implement minimal lifecycle primitives

Prefer exports such as:

```js
derivePromotionCandidates(operatorArtifacts)
applyPromotionEvent(state, event)
deriveEffectiveAttestations(candidates, events)
```

Use deterministic IDs/fingerprints, exact-key validation where practical, bounded fields, safe HTTP(S) references, append-only events, and at most one active attestation per source observable/claim.

### Step 4: Re-run focused test and confirm GREEN

```bash
node --test test/evidence-promotion.test.js
```

### Step 5: Commit

```bash
git add src/core/evidence-promotion.js test/evidence-promotion.test.js
git commit -m "feat: add analyst evidence promotion lifecycle"
```

## Task 4: Integrate promotion into Domain Investigation recommendations

**Files:**
- Modify: `src/core/domain-investigation.js`
- Modify: `test/domain-investigation.test.js`

### Step 1: Add failing authority-separation tests

Cover:
- unapproved candidate does not change recommendation;
- attestation-only evidence yields at most MONITOR;
- one known direct malicious family plus one active analyst attestation yields at most BLOCK_CANDIDATE;
- analyst attestation never increments provider-family vote count;
- revocation removes effective corroboration and recommendation downgrades while audit remains;
- rejection never contributes authority;
- superseded attestation does not double-count.

### Step 2: Confirm RED

```bash
node --test test/domain-investigation.test.js test/evidence-promotion.test.js
```

### Step 3: Integrate separate authority class

Keep provider Evidence v2 and analyst attestations separate in state and recommendation explanation. Derive effective attestations from candidate/event state. Never copy an attestation into provider evidence.

### Step 4: Confirm GREEN

```bash
node --test test/domain-investigation.test.js test/evidence-promotion.test.js test/provider-independence.test.js
```

### Step 5: Commit

```bash
git add src/core/domain-investigation.js test/domain-investigation.test.js
git commit -m "feat: integrate analyst attestations into recommendations"
```

## Task 5: Extend the existing Evidence Graph

**Files:**
- Modify: `src/core/evidence-graph.js`
- Modify existing Evidence Graph tests discovered in repository test suite
- Create adapter only if necessary: `src/core/domain-investigation-graph.js`

### Step 1: Add failing graph projection tests

Cover new deterministic nodes:
- `independence_group`;
- `operator_artifact`;
- `promotion_candidate`;
- `promoted_evidence`;
- `promotion_event`;
- `recommendation`.

Cover edges:
- provider `member_of` independence group;
- operator artifact `describes` observable;
- operator artifact `candidate_for` promotion candidate;
- candidate `derived_from` artifact;
- promoted evidence `promoted_from` artifact and `supports` observable;
- promotion event `affects` promoted evidence;
- recommendation `applies_to` observable;
- recommendation `based_on` provider evidence;
- recommendation `corroborated_by` analyst attestation;
- recommendation `quorum_from` known independence group.

Regression assertions:
- graph IDs/order remain deterministic;
- unknown lineage never produces a quorum edge;
- graph projection does not mutate source authority state;
- existing callers using old graph input still pass unchanged;
- graph bounds remain enforced deterministically.

### Step 2: Confirm RED

Run the focused graph test file with `node --test`.

### Step 3: Extend `buildEvidenceGraph()` additively

Add optional projection inputs/sections. Keep current signature compatible. Reuse current stable hashing, sort/freeze behavior, and bounds. If existing bounds are exhausted, use deterministic truncation/overflow summaries before increasing global limits.

### Step 4: Confirm GREEN

Run focused graph, promotion, provider-independence, and Domain Investigation tests.

### Step 5: Commit

```bash
git add src/core/evidence-graph.js src/core/domain-investigation-graph.js test/
git commit -m "feat: project investigation authority into evidence graph"
```

Only add the adapter file if tests prove the core graph needs a clean projection seam.

## Task 6: Preserve authority and audit context in report/handoff

**Files:**
- Modify: `src/core/domain-investigation.js`
- Modify: `test/domain-investigation.test.js`

### Step 1: Add failing report/handoff tests

Require public report/handoff output to preserve:
- known quorum groups and unknown lineage count;
- authority class for analyst attestations;
- promotion audit summary without dumping oversized raw artifacts;
- current effective attestation IDs/fingerprints;
- registry/version used for recommendation reconstruction;
- contradiction state.

### Step 2: Confirm RED

```bash
node --test test/domain-investigation.test.js
```

### Step 3: Implement bounded projections

Do not leak internal authoritative payloads wholesale. Keep handoff within existing Domain Investigation limits and maintain deterministic ordering.

### Step 4: Confirm GREEN and commit

```bash
node --test test/domain-investigation.test.js
```

Commit as `feat: expose investigation authority audit context`.

## Task 7: Add Shell parity

**Files:**
- Modify: `app/shell-core/catalog.js`
- Modify: `app/shell-core/runtime.js`
- Modify: `src/control/shell-node-executor.js`
- Modify existing shell tests

### Step 1: Add failing command tests

Add commands/actions for:
- `domain-investigation promotion-candidates`
- `domain-investigation promote <approval-json>`
- `domain-investigation reject-promotion <decision-json>`
- `domain-investigation revoke-promotion <decision-json>`
- `domain-investigation graph`

Require atomic state updates, sanitized/public `show`, bounded outputs, and volatile reset semantics.

### Step 2: Confirm RED using focused shell tests

### Step 3: Implement by calling core functions only

No provider calls, network fetch, scanning, or arbitrary execution. Failed promotion operations leave prior shell state unchanged.

### Step 4: Confirm GREEN and commit

Commit as `feat: add domain investigation promotion shell actions`.

## Task 8: Add MCP parity

**Files:**
- Modify: `src/mcp/server.js`
- Modify existing MCP tests

### Step 1: Add failing grouped-tool tests

Extend `para11ax_domain_investigation` with stateless/client-carried actions:
- `promotion_candidates`
- `promote`
- `reject_promotion`
- `revoke_promotion`
- `graph`

Require no server-side durable state, no scanning, bounded responses, and no global request-size increase.

### Step 2: Confirm RED with focused MCP tests

### Step 3: Implement minimal action routing

Reuse core modules and existing Domain Investigation body-limit exceptions only where exact build/import semantics require them. Do not widen MCP limits globally.

### Step 4: Confirm GREEN and commit

Commit as `feat: add domain investigation promotion MCP actions`.

## Task 9: Documentation and drift gates

**Files:**
- Modify: `docs/DOMAIN-INVESTIGATION.md`
- Modify: `docs/MCP.md`
- Modify: `docs/SHELL.md`
- Modify: `README.md` where capability lists require it
- Modify: `CHANGELOG.md`
- Modify drift/capability tests if repository contracts require them

### Step 1: Add/update drift tests first where applicable

The docs must state explicitly:
- provider names are not independence votes;
- unknown lineage is non-quorum;
- analyst attestations are corroboration, not provider votes;
- graph is projection, not authority;
- hosted execution remains passive.

### Step 2: Run drift/documentation tests and confirm expected failures

### Step 3: Update docs and capability metadata

Remove any historical wording that could imply `provider:<name>` fallback is quorum eligible.

### Step 4: Confirm GREEN and commit

Commit as `docs: document provider independence and evidence promotion`.

## Task 10: Full verification, review, and PR

### Step 1: Read required completion skills

Use:
- `superpowers:verification-before-completion`
- `superpowers:requesting-code-review`
- `superpowers:finishing-a-development-branch`

### Step 2: Run full repository verification

At minimum:

```bash
npm test
```

plus repository tooling smoke/drift commands required by CI.

### Step 3: Verify CI from GitHub

Require current branch/head checks green, including Tooling smoke, full tests, and CodeQL where configured. Do not infer success from an earlier SHA.

### Step 4: Review the complete diff against the approved design

Specifically search for forbidden semantics:
- provider-name fallback counted as BLOCK quorum;
- analyst attestation counted as provider vote;
- graph accepted as authority input;
- automatic promotion;
- hidden network/scanning behavior;
- global MCP payload widening.

### Step 5: Fix review findings test-first

Repeat focused and full verification after every material fix.

### Step 6: Open one clean follow-on PR

Base: `main`
Head: `feat/provider-independence-promotion-graph`

PR description must explain source-family quorum, manual promotion authority, graph projection, compatibility, and verification evidence.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
