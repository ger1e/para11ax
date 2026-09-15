<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->

# Provider Independence, Evidence Promotion, and Investigation Graph Design

> **Historical design record.** This document records the approved design snapshot from development and is not the current architecture. See `docs/ARCHITECTURE.md` for the authoritative current architecture.

**Status:** Approved design

**Date:** 2026-09-13

**Base:** Domain Investigation v1 on `main`

## Goal

Prevent false provider-consensus, let analysts deliberately promote bounded operator findings into canonical analyst attestations, and make the resulting authority/provenance chain explainable through the existing PARA11AX Evidence Graph.

This is a projection-first extension of existing PARA11AX models. It does not create a second investigation model, a second graph, or an automatic AI authority path.

## Design principles

1. Evidence v2 remains the root authority model for provider evidence.
2. Provider independence is source-family aware, not provider-name aware.
3. Missing or unknown lineage never establishes a second BLOCK vote.
4. Operator context remains non-authoritative until an analyst explicitly approves promotion.
5. Promoted evidence is a separate analyst authority class and never masquerades as an independent provider vote.
6. The existing Evidence Graph remains a deterministic projection/explanation layer, not mutable authority.
7. Existing Investigation and Domain Investigation artifacts remain the source of mutable case/workflow state.
8. All transitions are bounded, deterministic, auditable, fail-closed, and passive.

## Architecture

PARA11AX gains three connected extensions rather than three separate subsystems:

- **Provider independence metadata and resolver:** provider evidence may carry a normalized `independenceGroup` plus lineage metadata. Recommendation quorum counts distinct known, quorum-eligible source families instead of raw provider names.
- **Assisted evidence promotion:** bounded operator artifacts can generate deterministic promotion candidates. Candidates have zero authority. Explicit analyst approval creates immutable analyst attestations with preserved provenance and append-only audit events.
- **Extended Evidence Graph projection:** the existing `src/core/evidence-graph.js` graph is extended with provider-family, operator-artifact, promotion, analyst-attestation, recommendation, and audit relationships.

The Domain Investigation artifact and existing Investigation model remain case-state authorities. The graph is rebuilt from those authorities and canonical evidence; it is never trusted as input authority.

## Provider independence model

### Evidence provenance

Evidence v2 provider records may include an optional normalized provenance field:

```text
independenceGroup
```

The provider registry/resolver supplies lineage metadata:

```text
provider
independenceGroup
lineageConfidence = confirmed | probable | unknown
basis = declared | documented_upstream | maintained_mapping | fallback
references[]
updatedAt
quorumEligible
```

`provider` remains the raw source identity. `independenceGroup` represents the upstream evidence family used for consensus decisions.

### Conservative fallback rule

Unknown or missing lineage may retain a provider-specific display bucket for provenance/UI purposes, but that bucket MUST have:

```text
quorumEligible = false
```

It MUST NOT count as an independent group for BLOCK.

Therefore:

- two unknown-lineage providers do not satisfy a two-family BLOCK quorum;
- one mapped provider family plus one unknown-lineage provider does not satisfy a two-family BLOCK quorum;
- multiple wrappers/mirrors of one known upstream family count as one vote;
- only mapped, known, quorum-eligible families count toward BLOCK.

No provider-name fallback is permitted to create quorum eligibility.

### No probabilistic independence score in v1

The system uses explicit family mapping and eligibility, not an opaque numeric independence score. Lineage uncertainty is represented directly and remains visible in recommendation explanations.

## Recommendation quorum

The recommendation engine exposes both raw provider counts and independent-family counts, including the exact groups that contributed to quorum.

### BLOCK

`BLOCK` requires:

- at least two distinct known `quorumEligible=true` independence groups;
- direct malicious Evidence v2 on the exact IOC from those groups;
- no material contradiction that blocks/downgrades the recommendation.

### BLOCK_CANDIDATE

`BLOCK_CANDIDATE` may be reached with:

- one known direct-malicious provider family; and
- independent corroborating operator context or an approved analyst attestation.

An analyst attestation can increase actionability but cannot increment the provider-family vote count.

### MONITOR

`MONITOR` covers cases such as:

- promoted/operator/context evidence without sufficient direct provider quorum;
- direct malicious evidence whose lineage is unknown or non-quorum-eligible;
- otherwise relevant findings that do not meet block thresholds.

### DO_NOT_BLOCK

`DO_NOT_BLOCK` applies when direct malicious support is insufficient, or when material contradiction/shared-infrastructure/registration-only context makes blocking unjustified under the existing contradiction policy.

## Assisted evidence promotion

### Candidate generation

Promotion candidates are derived only from bounded operator artifacts that contain a valid observable/claim, source, capture timestamp, and provenance/reference.

A candidate is deterministic and has zero authority. Candidate generation must never change recommendations by itself.

Conceptual fields:

```text
id
sourceArtifactId
observable
observation
provenance
references
fingerprint
status
```

### Approval

Analyst approval creates an immutable canonical analyst-attestation record. The implementation may expose this as `promoted_evidence` externally, but the authority semantics are:

```text
authority = analyst_promoted
authorityClass = analyst_attestation
```

Fields include:

```text
id
sourceArtifactId
observable
observation
provenance
references
promotedAt / approvedAt
promotedBy / actorLabel
promotionReason / approvalReason
fingerprint
authority
authorityClass
```

The original operator artifact remains intact. The attestation preserves the exact source artifact ID, source/reference chain, analyst audit label, approval reason, and deterministic fingerprint.

`actorLabel` is audit attribution only. It MUST NOT be represented as cryptographically authenticated identity unless the surrounding platform actually supplies authenticated identity context.

### Lifecycle

```text
operator artifact
  -> promotion candidate
     -> approved -> active analyst attestation
     -> rejected
     -> expired

active analyst attestation
  -> superseded -> historical
  -> revoked -> historical
```

Recommended internal model:

```text
promotionCandidates[]  // deterministic derived projection
promotionEvents[]      // append-only: approved, rejected, revoked, superseded
 effectiveAttestations[] // derived current-state projection
```

Rules:

- no recursive promotion;
- a rejected candidate stays rejected unless the source artifact materially changes and produces a new fingerprint;
- revocation never deletes history;
- supersession preserves prior fingerprints and audit history;
- at most one active attestation per source-observable-claim tuple;
- invalid transitions fail atomically and leave original state unchanged.

## Authority boundaries

Analyst-promoted evidence is canonical for correlation, reporting, handoff, and graph traversal, but it is a separate authority class from provider Evidence v2.

An approved analyst attestation:

- may corroborate provider evidence;
- may raise MONITOR to BLOCK_CANDIDATE when one known malicious provider family exists;
- may participate in correlation and Evidence Graph paths;
- MUST NOT count as a provider-family vote;
- MUST NOT by itself satisfy BLOCK quorum.

An unapproved promotion candidate has zero recommendation impact.

## Existing Evidence Graph extension

The existing `src/core/evidence-graph.js` remains the single canonical graph implementation.

### New node types

Additive node classes:

```text
independence_group
operator_artifact
promotion_candidate
promoted_evidence
recommendation
promotion_event
```

Existing observable, provider, evidence, actor, malware, ATT&CK, CVE, ASN, CIDR, certificate, domain, URL, IP, and hash graph concepts remain compatible.

### New relationships

```text
provider -> member_of -> independence_group
evidence -> supports -> observable
evidence -> reported_by -> provider
operator_artifact -> describes -> observable
operator_artifact -> candidate_for -> promotion_candidate
promotion_candidate -> derived_from -> operator_artifact
promoted_evidence -> promoted_from -> operator_artifact
promoted_evidence -> supports -> observable
promotion_event -> affects -> promoted_evidence
recommendation -> applies_to -> observable
recommendation -> based_on -> evidence
recommendation -> corroborated_by -> promoted_evidence
recommendation -> quorum_from -> independence_group
```

Recommendation nodes carry enough deterministic explanation data to reconstruct why a disposition was produced, including:

```text
ruleId
disposition
uniqueQuorumGroups
contradictions
evidenceFingerprints
```

### Graph authority rule

The graph is a deterministic projection/search/explanation layer only. It never becomes mutable source-of-truth state and is never accepted as evidence authority input.

Graph expansion does not trigger provider queries, scanners, arbitrary fetches, or network execution.

### Bounds

Keep existing graph bounds unless tests demonstrate that deterministic overflow handling must be extended. Prefer stable omission/summary behavior to unbounded graph growth.

## Domain Investigation integration

Domain Investigation projects into the existing Evidence Graph through an adapter/projection path. Required traversals include:

- domain/IOC -> supporting malicious evidence -> providers -> independence groups;
- operator finding -> promotion candidate -> approved analyst attestation;
- recommendation -> supporting evidence -> quorum groups;
- recommendation -> corroborating analyst attestations;
- recommendation -> contradiction evidence/context.

Domain Investigation remains passive. No hosted active scanner or arbitrary target execution is added.

## Shell and MCP integration

Core semantics land before interface extensions.

After the core model is stable, extend the existing Domain Investigation interfaces with actions such as:

```text
promotion-candidates / promotion_candidates
promote
revoke-promotion / revoke_promotion
graph
recommendations
```

Exact action names should follow existing Shell/MCP naming conventions.

MCP remains stateless and client-carried. Shell state remains volatile unless explicitly backed by the existing Investigation model. No global MCP body-limit widening is allowed; any larger payload allowance remains scoped to the Domain Investigation grouped tool and valid action shapes.

## Validation and security

All new state transitions and metadata use exact-key validation where current PARA11AX conventions require it.

Required constraints:

- bounded strings, counts, arrays, and payloads;
- safe HTTP(S) references only where references are permitted;
- no credentials/secrets in promotion sources or references;
- malformed or unmapped candidate references fail closed;
- imported operator artifacts remain context until explicit approval;
- unknown lineage is `quorumEligible=false`;
- no silent automatic authority transition;
- no arbitrary external fetch or scanner execution;
- invalid promotion operations are atomic;
- stale and contradictory evidence remain visible;
- outputs are deterministic for audit and tests;
- actor labels are audit labels, not authentication claims;
- graph data is derived and never trusted as input authority.

## Migration and compatibility

The change is additive where possible.

- Existing Evidence v2/provider records without `independenceGroup` remain valid.
- Missing lineage resolves to unknown/non-quorum-eligible, never to an independent provider vote.
- Existing Evidence Graph callers continue to work with optional new fields/nodes/edges.
- Existing Domain Investigation and Investigation artifacts remain readable.
- Promotion data is separate from provider Evidence v2 semantics.
- Historical evidence is not rewritten by migration.
- Recommendation output should retain existing top-level fields where practical and add explicit independence/authority explanation.
- Version bumps are required only where semantic compatibility cannot be preserved.
- MCP global payload ceilings remain unchanged.

Where provider-family mappings are maintained outside historical evidence, recommendation/audit output must record enough resolver/mapping version context to reconstruct decisions later.

## TDD contract

The implementation must prove at least the following cases:

1. Two providers from the same mapped independence group equal one direct vote.
2. Two known, distinct, quorum-eligible groups can reach BLOCK when exact direct-malicious support exists and no blocking contradiction exists.
3. Two unknown-lineage providers cannot reach BLOCK.
4. One known group plus one unknown-lineage provider cannot satisfy two-family BLOCK quorum.
5. Wrapper/mirror providers mapped to one upstream family do not create false independence.
6. Promotion candidate generation is deterministic across input order.
7. An unapproved promotion candidate has zero recommendation impact.
8. Approval creates an immutable analyst attestation with intact provenance.
9. One known malicious provider family plus one approved analyst attestation reaches at most BLOCK_CANDIDATE.
10. An analyst attestation never increments provider-family quorum.
11. Rejection grants no authority.
12. Revocation removes effective corroboration while preserving audit history.
13. Supersession preserves old fingerprints and historical events.
14. Malformed/oversized promotion operations fail atomically.
15. Graph output is deterministic, bounded, and preserves provider-family/provenance paths.
16. Recommendation support and contradiction paths are visible in the graph.
17. Report/handoff preserve authority class and promotion-audit summary.
18. Order/property invariance holds for deterministic projections.
19. Secrets/unsafe references are rejected or safely excluded according to existing validation policy.
20. Shell/MCP parity is tested only after core semantics are stable.
21. A fixture with multiple wrapper providers sharing one underlying family proves false-independence prevention.
22. Documentation/capability drift tests are updated where the repository enforces them.

## Non-goals

This design does not add:

- automatic LLM promotion;
- automatic analyst approval;
- arbitrary hosted scanning;
- provider-name-based independence quorum;
- a second Evidence Graph implementation;
- a second Investigation/case authority model;
- probabilistic provider-independence scoring;
- cryptographic analyst identity where no authenticated identity exists;
- deletion of historical promotion decisions.

## Acceptance criteria

The feature is acceptable when:

- BLOCK consensus cannot be fabricated by multiple providers sharing one upstream family;
- unknown-lineage evidence cannot silently become a second BLOCK vote;
- operator context can be promoted only through explicit analyst approval;
- promoted evidence remains a distinct authority class and never counts as provider quorum;
- every promotion/revocation/supersession is auditable and deterministic;
- Domain Investigation projects the complete evidence/quorum/promotion explanation into the existing Evidence Graph;
- existing callers remain compatible or are migrated with explicit schema/version handling;
- full repository tests, Tooling smoke, CodeQL, and relevant production/conformance gates pass on the final head.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
