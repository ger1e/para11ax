<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Changelog

All notable repository changes should be recorded here. This project uses a lightweight chronological changelog rather than claiming semantic-versioning guarantees for personal lab workflows.

#### Unreleased

##### Added

- **GreyNoise Project Swarm integration** delivered across PRs #207–#209:
  - PR #207 / `dfb3ef854885321f175ef588d5b8398c86baedc2` upgraded canonical GreyNoise IP enrichment to the authenticated v3 IP Lookup and added bounded Project Swarm workspace-label handling (`greynoise,community,personal` by default, optional `GREYNOISE_WORKSPACE_LABELS`).
  - PR #208 / `76030561a6b4b78131d6a32f5084e0620535aad7` added the authenticated Web-only Swarm session route with `swarm search`, `swarm get`, and explicit single-session `swarm export` for PCAP/raw-source/raw-destination.
  - PR #209 / `ec3cac395693cc448a7bfada5ed7cd6c9ff68000` added allowlisted `swarm unique` and `swarm timeseries` pivots plus explicit `investigation capture operator` support for bounded Swarm read results.
- Swarm fixed egress to `https://api.greynoise.io`, server-side-only `GREYNOISE_API_KEY`, strict ISO-8601 range validation, 2,048-character printable query ceiling, page/page-size/timeseries/field allowlists, 4 MiB JSON/export ceilings, redirect refusal, and local rejection of demo export/bulk session export.
- Explicit GreyNoise scope/entitlement documentation: `scope=workspace` depends on the applicable Sensors entitlement; `scope=demo` depends on the applicable Swarm entitlement; repository/configuration state does not prove either entitlement.
- **Investigation Workspace v2** with one canonical browser-local aggregate covering scope, observables, Evidence v2 snapshots/diffs, operator context, mission workflow, imported results, analyst disposition, dependency freshness, reports, ServiceNow projection, notes, and timeline.
- Twenty-two registered `investigation` commands with exact `inv` aliases, compact mutation receipts, active status-line identity/phase, explicit browser file transport, and pure CLI show/status/import/export via exact `--file` or `--stdin`.
- Lossless bounded migration for compatible case v1.0 records and explicit validated Mission Workspace v1 adoption; oversized legacy records fail closed without truncation.
- Deterministic dependency fingerprints, stale-artifact gates, atomic one-write repository mutations, canonical 4 MiB bundles, and report/ticket refusal when required dependencies are stale.
- **Mission Workspace v1** shared across Web and CLI: deterministic client relevance, hunt-package construction, conservative KQL validation, bounded JSON/CSV result analysis, ServiceNow-ready projection and canonical portable bundle import/export.
- Twelve registered `mission` commands backed by one shared adapter and frozen reducer, with byte-identical Web/CLI exports, exact downstream invalidation, atomic failures and explicit browser/CLI file transports.
- **Provider Value Scheduler v1.0** with deterministic static execution ordering over already-admitted providers. The current 24-provider IP workflow remains unchanged, with a 48-call ceiling, max concurrency 4, maximum two attempts/provider and 20-second request deadline.
- Declarative scheduler metadata for provider authority, semantic uniqueness, direct threat value, pivot value, latency and cost classes, with deterministic fallback and public capability projection that excludes credentials/internal runtime rank state.
- **Intelligence Kernel v1.0** IP reference projection for deterministic evidence strength, source diversity/independence, corroboration, contradiction severity, temporal relevance, explicit relationship value, bounded one-hop pivots, threat context, hunt relevance, capability-aware coverage impact, analyst priority, limitations and trace rule IDs.
- Kernel-aware Decision Support mapping with guarded legacy fallback for absent/malformed/wrong-version/wrong-type intelligence.
- Bounded Intelligence Kernel summary in Guidance while Evidence Graph fingerprint validation remains authoritative.
- Kernel-backed IP analyst report using one shared deterministic model for executive assessment, relationships/pivots, contradiction severity, temporal context, hunt relevance, coverage and copy/text output.
- Compatibility locks keeping Evidence v2 authoritative, Evidence Graph/STIX isolated from Kernel-derived conclusions, legacy/cached envelopes valid, and deterministic outputs permutation-safe.
- Repository-wide **GER1E/PARA11AX documentation standard v1** across every tracked Markdown surface: shared standard marker/footer, current terminology and proof-state vocabulary, GER1E-normalized README sizing, supporting README/template parity, and explicit historical-status banners on preserved Superpowers plans/specs.
- GER1E-normalized README sizing contract: 720px SVG family, 102px hero mark, 22px headings, 17px body, 15px microtype, 13/12px hero rain, and full-width 720×300 terminal footer with `PER ASPERA AD ASTRA`.
- Native bounded Shodan analyst-shell surface with authenticated `shodan host`, `search`, `count`, `stats`, `domain`, and `info` commands through same-origin `POST /api/para11ax/shodan`.
- Fixed Shodan shell egress to `https://api.shodan.io` with server-side-only `SHODAN_API_KEY`, first-page-only search, capped normalized results, raw banner stripping, disabled `download`/arbitrary paging, and explicit query-credit impact.
- V8 Train 4 browser-local case workspace with IndexedDB persistence, bounded `.para11ax` bundles, snapshots/semantic diffs, exact typed cross-case index and local case graph projection.
- V8 Train 5 canonical Evidence Graph v1.0 and Guidance v1.0 projections.
- V8 Train 6 certificate Maltego parity across all nine gateway workflow types with explicit `cert-sha256:` semantics.
- Executable documentation-contract drift checks for workflow types, provider count, scheduler/Kernel contracts, API routes, evidence projection versions, Maltego coverage, production identity, User Scanner, Shodan shell, GreyNoise Swarm, README visual sizing, and repository-wide Markdown standardization.
- Evidence-oriented QA report and proof-state model separating repository, CI, deployment, live-public and credential-dependent verification.
- Public-release safety audit/checklist, architecture/trust-boundary/security-control docs, contribution guidance and operator CLI/report workflows.

##### Changed

- The unified shell now documents GreyNoise Swarm as a Web-only specialist operator family distinct from the canonical GreyNoise Evidence v2 provider.
- Investigation Workspace operator capture now explicitly supports compatible GreyNoise Swarm `search`, `get`, `unique`, and `timeseries` results as contextual records; Swarm binary exports remain download-only and outside automatic Evidence v2 promotion.
- The unified shell includes a volatile `mission` namespace. Browser mission state clears on disconnect/reboot and persists across auth clearing; CLI state is process/pipeline-local and reads files or stdin only when explicitly requested.
- Public README and all current deep docs now describe the merged deterministic Scheduler/Kernel architecture instead of the retired provider-order wording.
- Every tracked Markdown document uses the same GER1E/PARA11AX standard; historical Superpowers plans/specs retain their original technical record but are explicitly labeled historical and point to the current architecture.
- Evidence v2 remains the authoritative provider-normalized record; Intelligence Kernel output is explicitly documented as derived context rather than new evidence.
- Provider execution ordering is separated from profile admission. Scheduler priority cannot broaden provider membership or use earlier evidence to suppress admitted sources.
- IP reporting, Decision Support and Guidance consume a compatible Intelligence Kernel v1.0 projection while preserving established fallbacks.
- Documentation distinguishes Evidence v2 relationships, Kernel derived relationship/pivot context, `decision.entityGraph`, canonical Evidence Graph v1.0, browser-local case graph, and separate contextual operator records.
- Analyst-shell documentation distinguishes canonical Evidence v2 enrichment, isolated User Scanner active OSINT, bounded native Shodan operator lookups, and bounded GreyNoise Swarm session operations. Specialist operator output does not automatically mutate Evidence v2 / Kernel state.
- Completed the PARA11AX identity migration across repository/package metadata, CLI, bearer/env names, API paths, Maltego properties, GitHub links and `https://para11ax.vercel.app`; legacy aliases remain unsupported.
- Hardened landing/analyst UI first-paint behavior and expanded the canonical observable surface to nine bounded workflows: IP, domain, URL, file hash, CVE, ATT&CK, ASN, CIDR and explicit certificate SHA-256.
- npm dependency state is lockfile-backed; CI performs deterministic install/audit.
- Report generation remains offline-only, bounded and deterministic for a frozen gateway snapshot and supplied generation timestamp.

##### Security

- GreyNoise Swarm accepts only five bounded operations, fixed scopes and vetted pivot fields/intervals/export types; rejects caller-selected URL/method/header/credential/bulk-export behavior; keeps `GREYNOISE_API_KEY` server-side; refuses redirects; caps JSON and individual exports at 4 MiB; and preserves operational failures as failures rather than threat evidence.
- Swarm session/pivot context is not Evidence v2. Explicit Investigation Workspace operator capture does not manufacture maliciousness, ATT&CK mapping, corroboration or disposition; PCAP/raw export is never automatically attached or promoted.
- Investigation v2 adds no provider, host, credential, network method, runtime dependency, LLM, KQL execution, ServiceNow submission, or server persistence. Recursive closed-schema validation rejects hostile JSON structure, secret-shaped keys, unsafe URLs, invalid fingerprints/timestamps, forged status, and bound violations.
- Mission Workspace adds no model/provider call, egress, secret read, dependency, dynamic execution, server-side persistence, KQL execution or ServiceNow submission. Imports reconstruct derived projections and reject tampering; analyst approval remains mandatory.
- Provider Value Scheduler v1.0 changes only deterministic attempt order among admitted providers; it adds no provider, host, credential, method, protocol or evidence-dependent suppression path.
- Intelligence Kernel v1.0 is deterministic/read-only and adds no network egress, secret/environment read, dependency or persistence surface. It uses no LLM, runtime learning or universal maliciousness score.
- Kernel projection failure is isolated: usable Evidence v2 survives and the missing projection is surfaced as an explicit limitation.
- Provider failures/skips remain coverage facts; capability-aware coverage impact never converts unavailable sources into benign/negative threat evidence.
- Kernel pivots are explicit one-hop normalized relationships only; free text cannot manufacture related infrastructure; Evidence Graph/STIX do not promote Kernel-derived conclusions as new evidence.
- Shodan shell accepts only six approved commands, rejects caller-selected URLs/methods/pages/credentials, exposes no on-demand scan submission, keeps `SHODAN_API_KEY` server-side, and surfaces rate/credit state without converting failures into negative Evidence v2.
- Shodan search is first-page only; result/service arrays are bounded; large raw service banners are removed; `shodan download` is disabled.
- Browser-local cases remain IndexedDB-only; active case/auth state is runtime-only and the workspace adds no server-side IOC history.
- Public publication remains a separate review event; file-based controls complement external GitHub/Vercel account settings.
- Raw report snapshots are secret-scanned; sharing presets fail closed on restricted/unknown distribution; CSV exports neutralize formula prefixes; report quality gates reject unsafe claims/provenance/attribution/timestamps/references.

##### Verification note — 2026-08-30

Provider Value Scheduler v1.0 + Intelligence Kernel v1.0 merged as `11d7b861d9f626c45f44c138c8d72cee9493efdf` and passed Tooling smoke 1374 plus CodeQL 962. Vercel then rejected the production deployment on a Hobby-plan build/deployment rate limit; the latest READY production at that audit point remained `2acc19f0558b1c3bbbcd96b47b8da69a25192c55`. Repository/CI proof therefore did not equal production deployment proof, and authenticated protected enrichment was not claimed as exercised.

##### Verification note — 2026-09-06

GreyNoise Project Swarm source integration is represented by PRs #207–#209 and their exact merge SHAs listed above. Repository/CI/deployment route presence must remain distinguished from credentialed GreyNoise proof: no documentation claim should infer a working production `GREYNOISE_API_KEY`, Sensors entitlement, Swarm entitlement or workspace export entitlement unless an authorized live operation on the exact deployment demonstrates it.

#### 1.0.0

Initial personal-research implementation of the read-only PARA11AX gateway, bounded Maltego client, provider normalization layer, CI verification and Vercel bootstrap/deployment workflow.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>