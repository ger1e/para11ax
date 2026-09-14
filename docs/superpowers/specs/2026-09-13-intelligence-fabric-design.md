<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# Intelligence Fabric Design

## Goal

Extend PARA11AX from baseline enrichment into a bounded provenance-first intelligence fabric without turning the gateway into an unrestricted API proxy or a collection of integrations that require separate commercial subscriptions.

## Source Strategy

The fabric prefers public, nonprofit, community, free or low-friction sources, plus integrations already established in the baseline gateway. New paid-only provider expansion is outside this design. A source is admitted only when it contributes a distinct evidence class or relationship that justifies its operational cost and complexity.

## Execution Model

Supported capability modes are `enrich`, `graph`, `search`, `monitor`, `analysis`, and `knowledge`. Baseline `enrich` remains the only automatically fanned-out mode. Secondary capabilities are explicit and non-fanout until benchmark evidence supports promotion.

Sensitivity classes remain `public`, `owned_asset`, `pii`, `credential`, `secret`, and `sample`. Authorization classes remain `none`, `tenant`, `verified_domain`, `owned_network`, `explicit_case`, and `explicit_action`. Authorization is server-created and never caller self-asserted.

## Evidence Boundaries

Every provider returns bounded normalized evidence with source identity, retrieval provenance, parser version, semantic class, retention class, distribution policy, and explicit relationships. Provider presence is never equivalent to maliciousness. Absence is represented as `no_result`/`not_found`, not as a clean verdict unless the upstream source explicitly asserts one.

Context, knowledge, reputation, vulnerability metadata, exploitation state, supply-chain relationships, historical web observations, network identity, secret exposure, crypto-abuse context, and owned-asset exposure remain semantically distinct.

## Retained Capability Families

The approved fabric keeps bounded graph/search/history additions for already-established infrastructure services and the following low-friction additions:

- exploit-maturity context and package dependency relationships;
- passive TLS/malware context and malware configuration/similarity;
- historical web observations;
- defensive knowledge;
- crypto-abuse context;
- privacy-preserving secret exposure checks;
- owned-network reports with server-controlled scope;
- free IP-to-ASN/network identity context.

No arbitrary base URLs, arbitrary methods, write-like upstream operations, unbounded pagination, or caller-selected trust flags are permitted.

## Owned-Asset Boundary

Owned-network monitoring is a separate capability. The canonical subject must match trusted deployment scope before execution. Deployment CIDR/domain scope may augment a trusted server authorization context, but public callers cannot inject ownership claims.

## Privacy Boundary

PII-capable features use explicit bounded paths and no-store handling where appropriate. Raw secrets are never sent to secret-exposure services. Existing username search remains isolated from enrichment fanout.

## Admission and Cost Control

Provider value is measured by unique facts, unique graph edges, decision-changing observations, latency, errors, no-result rate, and material unique observations per call. Reliability alone does not justify automatic admission. Duplicative sources with no unique value remain explicit or are removed.

## Release Boundary

Every wave must preserve fixed-host egress, bounded requests and responses, deterministic manifests, secret-safe output, exact-head CI, CodeQL, and protected-PR deployment flow. Production promotion occurs only after the final integration gates pass.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
