<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical gap-closure plan. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# Intelligence Fabric Gap-Closure Plan

## Goal

Close only the remaining high-value gaps in the bounded Intelligence Fabric without adding new paid-only provider dependencies or broadening default enrichment fanout.

## Current State

The fabric already has:

- deterministic capability policy and intelligence-only observables;
- fixed-host provider egress and normalized evidence;
- explicit graph/search/monitor/analysis/knowledge modes;
- central trusted authorization;
- bounded second-phase pivots;
- isolated username search;
- exploit, supply-chain, TLS/malware, historical-web, defensive-knowledge, crypto-abuse, secret-fingerprint, owned-network, and free network-identity capabilities.

## Gap G1: Username Search Integration

**Status:** Implemented.

The normalized intelligence search surface delegates username searches to the existing bounded User Scanner path. It remains isolated from baseline enrichment, retains no shared-cache material, and preserves workload identity without exposing caller-selected provider routing.

## Gap G2: Provider Value Benchmark and Admission

**Status:** Remaining.

Add an offline deterministic benchmark/admission layer that measures:

- unique facts per call;
- unique graph edges per call;
- decision-changing observations;
- material unique observations;
- p50/p95 latency;
- error rate;
- no-result rate;
- overlap/duplication against already-admitted sources.

A source must not enter automatic fanout merely because it is available or reliable. Zero-unique-value sources fail admission by default. High-value but slow or quota-sensitive sources may remain explicit graph/search capabilities.

## Source Policy

Future source work should prefer public, nonprofit, community, free or low-friction intelligence and existing baseline integrations. Paid-only expansion is explicitly out of scope for this plan. New sources still require fixed hosts, bounded operations, truthful absence semantics, provenance, and measured unique value.

## Release Gate

After provider admission work:

1. write a cross-mode E2E fixture;
2. run `npm test` and `npm run check`;
3. run MCP, Maltego, PowerShell, governance, secret-safety, and CodeQL gates;
4. verify the exact PR head is green and mergeable;
5. review egress hosts, request bounds, distribution/retention policy, and default-workflow membership;
6. merge only through protected-main flow;
7. verify production deployment SHA and run bounded production smoke tests.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
