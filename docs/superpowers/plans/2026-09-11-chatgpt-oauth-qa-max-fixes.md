<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md) and the current README.

# ChatGPT OAuth MCP QA Max Fix Plan

**Goal:** Turn the 2026-09-11 live ChatGPT OAuth/MCP QA failures into regression-covered fixes without weakening PARA11AX safety boundaries.

## Fix Set

1. Add regression tests for deterministic STIX IDs, header normalization, GreyNoise entitlement-safe defaults, batch partial status propagation, CVSS normalization, persistent KEV freshness, hash canonicalization, GHSA hunt suppression, noisy single-provider pivot suppression, User Scanner confidence classification, explicit Swarm MCP schema, provider runtime-health projection, and stable repeated MCP tool discovery.
2. Fix the shared JSON fetch wrapper so caller-supplied headers override defaults case-insensitively.
3. Stop adding GreyNoise `workspace_labels` unless explicitly configured; default to the provider's global dataset.
4. Replace random STIX IDs with stable UUIDv5-style IDs by default while retaining dependency injection for tests.
5. Preserve nested enrichment status in batch results and distinguish completion from enrichment quality.
6. Normalize CVSS object payloads into correlation risk axes and treat fresh persistent-state claims such as CISA KEV membership as current state.
7. Canonicalize hash observables/relationships case-insensitively and suppress self-pivots at graph/hunt projection boundaries.
8. Gate generated hunt pivots: reject advisory aliases as Defender CVEs, suppress noisy single-provider passive-DNS hostname pivots, and require stronger relationship support for derived hunts.
9. Downgrade User Scanner search-result/generic-endpoint matches to unverified indicators instead of counting them as confirmed finds.
10. Publish a fully self-describing GreyNoise Swarm MCP input schema.
11. Add provider `runtimeHealth`/outcome data to status so configured/active is not presented as runtime success.
12. Re-run focused tests, full repository checks, security analysis, production MCP smoke checks, compare branch vs main, and merge only after verification.

## MCP Lifecycle Note

The live ChatGPT namespace loss may be client/plugin lifecycle behavior rather than a server mutation. PARA11AX adds repeated discovery/list regression coverage and keeps the tool catalog immutable. Do not invent a transport workaround unless the server-side test reproduces a mutation or protocol defect.
