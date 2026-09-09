<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX QA Report

## Scope and audit baseline

Audit record updated: 2026-09-09.

This report covers repository behavior, browser surfaces, deterministic intelligence runtime, specialist operator surfaces, Maltego integration, CI controls, deployment metadata, public production behavior, and static-response security boundaries. Repository source, CI, deployment metadata, live public checks, credentials, vendor account entitlements and authorized data-bearing probes remain separate proof states.

### Preserved 2026-09-02 audited deployment baseline

The protected-`main` baseline audited on 2026-09-02 was:

```text
bfb8bd03c410ab2d0e15d3c64fbb2747730d9503
```

External verification on that exact SHA:

```text
Tooling smoke — PASS
Vercel para11ax — READY / PASS
Vercel user-scanner — PASS
```

The accepted PARA11AX production deployment at that audit was:

```text
dpl_538ViS14ukerEUYWBDkX9EPF4NX2
```

Vercel reported that deployment as `READY`, production-targeted, and sourced from the exact audited SHA. Live browser QA exercised the landing page, app boot, boot skip/handoff, terminal help, and public provider discovery without application-origin console errors. Vercel reported no grouped runtime errors for the PARA11AX or User Scanner projects over the preceding seven days. Authenticated protected enrichment was not exercised because that audit did not use bearer or provider credentials.

Local verification on the audited tree completed 1,011 Node tests, 66 Maltego unit tests, Python compilation, repository invariants, the dependency audit, and the public-release audit. The local environment did not include ShellCheck, so the aggregate `npm run check` wrapper stopped at that preflight; the exact-main Tooling smoke status independently passed the ShellCheck-bearing CI gate.

Historical Scheduler/Kernel closure remains recorded for traceability: `11d7b861d9f626c45f44c138c8d72cee9493efdf`, Tooling smoke 1374 — PASS, CodeQL 962 — PASS, while production was still `2acc19f0558b1c3bbbcd96b47b8da69a25192c55` under the earlier deployment-rate limit. Those values are evidence for the 2026-08-30 checkpoint, not a claim about the newest deployment.

### GreyNoise Project Swarm functional source baseline — 2026-09-06

The Swarm functional integration reached protected `main` through three changes before this documentation refresh:

```text
PR #207  dfb3ef854885321f175ef588d5b8398c86baedc2  authenticated GreyNoise v3 IP lookup / workspace-label integration
PR #208  76030561a6b4b78131d6a32f5084e0620535aad7  Swarm search/get/single-session export
PR #209  ec3cac395693cc448a7bfada5ed7cd6c9ff68000  Swarm unique/timeseries + investigation operator capture
```

The Swarm source contract includes fixed `https://api.greynoise.io` egress, server-side `GREYNOISE_API_KEY`, five approved Web operations (`search`, `get`, `unique`, `timeseries`, `export`), explicit range/query/page/pivot/export bounds, 4 MiB JSON/single-export ceilings, local demo-export rejection, and explicit operator-context isolation from Evidence v2.

This source baseline does **not** prove that a production `GREYNOISE_API_KEY` is configured, that `scope=workspace` has the applicable Sensors entitlement, that `scope=demo` has the applicable Swarm entitlement, or that workspace export is authorized. Those require explicit credential-bearing acceptance on the exact deployment.

## Proof-state definitions

- **Repository-proven:** static source/tests executed for one exact Git tree/SHA.
- **CI-proven:** a GitHub workflow completed successfully for one exact SHA.
- **Deployment-proven:** Vercel reports a deployment in `READY` state whose `githubCommitSha` equals the expected exact SHA.
- **Live-public-proven:** public unauthenticated routes return expected status/content from the accepted deployment.
- **Configured:** required runtime credential/wiring exists; source alone cannot prove it.
- **Vendor-entitled:** the upstream account accepts the exact scope/operation; configuration alone cannot prove it.
- **Credential-dependent / not proven by public QA:** authenticated health/status, provider secret configuration, User Scanner wiring, `SHODAN_API_KEY` configuration, GreyNoise credential/scope/export entitlement, vendor account/credit state, and credentialed upstream readiness unless an authorized check actually executes.

These states are intentionally not interchangeable.

## Current architecture QA contract

### Provider Value Scheduler v1.0

The implementation and documentation must agree that:

- provider admission remains fixed by workflow/profile;
- the Scheduler deterministically orders already-admitted providers;
- the current IP reference path is a **24-provider IP workflow**;
- the IP **48-call ceiling** remains 24 × maximum two attempts;
- max provider concurrency remains 4;
- request deadline remains 20 seconds;
- no evidence-dependent source suppression is allowed;
- malformed/missing scheduler descriptors fall back deterministically;
- scheduler metadata does not add hosts, credentials, methods or a threat score.

### Intelligence Kernel v1.0

The implementation and documentation must agree that:

- Kernel output is deterministic derived context, not Evidence v2;
- Evidence v2 remains authoritative;
- current reference policy is IP-first;
- source diversity distinguishes independent corroboration from duplicate capability;
- contradictions stay explicit and carry severity;
- temporal relevance uses observation timestamps rather than retrieval time;
- relationships/pivots are explicit, stable and bounded to one hop;
- provider failures/skips become coverage impact only, never benign/negative threat evidence;
- Decision Support consumes a compatible Kernel projection with guarded legacy fallback;
- Evidence Graph remains isolated from Kernel-derived relationships;
- Guidance exposes only a bounded Kernel summary with existing evidence-fingerprint validation;
- IP structured/copy report output consumes the same Kernel-backed model;
- no new network, credential/environment, persistence or dependency surface exists;
- no LLM, runtime learning or universal maliciousness score exists.

## Findings and dispositions

### QA-001 — architecture omitted the certificate workflow

**Disposition:** fixed. Documentation and executable checks cover all nine Evidence v2 workflow types.

### QA-002 — Evidence Graph/Guidance contracts were under-documented

**Disposition:** fixed with first-class projection documentation and explicit error-envelope boundaries.

### QA-003 — Maltego documentation lagged certificate parity and CI topology

**Disposition:** fixed. Maltego covers all nine workflow types, explicit `cert-sha256:` transport, and bounded Ubuntu Tooling smoke topology.

### QA-004 — changelog lagged major V8 capabilities

**Disposition:** fixed and covered by drift checks.

### QA-005 — contribution/security prose contained stale repository-state language

**Disposition:** fixed. Repository files distinguish governance intent from external GitHub/Vercel/vendor state.

### QA-006 — public/operator docs under-described graph/local-state boundaries

**Disposition:** fixed by separating decision-local graph, canonical Evidence Graph, browser-local case graph, Guidance, operator context and persistence boundaries.

### QA-007 — Shodan runtime existed before public/operator documentation caught up

**Disposition:** fixed. README, API, architecture, providers, operations, security controls, threat model, security policy, changelog, QA/release guidance and dedicated `docs/SHODAN-SHELL.md` describe the bounded six-command Shodan surface and Evidence v2 isolation.

### QA-008 — Provider Scheduler / Intelligence Kernel merged before public docs were current

**Proof:** merge `11d7b861d9f626c45f44c138c8d72cee9493efdf` introduced deterministic scheduling and Intelligence Kernel v1.0, while the public README/deep docs still described the older provider-order/correlation path and architecture artwork still used retired scheduler wording.

**RED evidence:** documentation-normalization PR #182 added `test/docs-current-ger1e-normalization.test.mjs` before public-doc changes. Tooling smoke run 1400 reached 835 Node tests with 830 passing and exactly five new documentation/GER1E contract tests failing. Existing runtime tests remained green; failures were limited to the missing full-width footer, stale README/architecture/provider content and missing Kernel/security documentation.

**Disposition:** fixed. The public documentation and README SVG family describe the Scheduler/Kernel architecture using the GER1E 720px / 102-22-17-15 / 13-12 sizing system, with executable drift checks in the Node suite.

### QA-009 — static browser responses lacked an explicit security-header policy

**Proof:** the live root response exposed HSTS but no explicit CSP, clickjacking, MIME-sniffing, referrer, cross-origin isolation, or permissions policy. API JSON already applied its own response controls, leaving the HTML/static boundary inconsistent.

**Root cause:** the deployable configuration mixed a top-level modern `headers` rule with a legacy `routes` pipeline. The repository's structural test validated the unused top-level rule, while the production legacy route chain emitted none of those headers.

**RED evidence:** the 2026-09-09 repair first changed the regression test to require the complete policy on a global continuing legacy route. The test failed because no such rule existed; the live root, app, and branded 404 responses independently reproduced the missing policy.

**Disposition:** fixed in the deployment candidate by making the complete policy the first continuing rule in the active legacy route pipeline, covering landing, app, assets, API, and branded error pages. Repository closure requires the focused and full suites; production closure additionally requires a READY deployment from the accepted exact `main` SHA and live header checks against root, app, and an HTML error response.

### QA-010 — GreyNoise Swarm runtime outpaced cross-repository documentation

**Proof:** PRs #207–#209 added canonical GreyNoise v3 IP behavior, Swarm session operations, pivots and investigation operator capture while several current README/deep-doc surfaces still described only User Scanner/Shodan operator utilities and the API inventory omitted `/api/para11ax/swarm`.

**TDD guard:** the documentation refresh first expanded `test/documentation-contracts.test.mjs`. On the test-only head, Tooling smoke failed with exactly the new documentation gaps: API docs missing `swarm` and unified public docs missing the Swarm shell contract, while the existing test suite remained otherwise green.

**Disposition:** this documentation refresh aligns README, API, shell, architecture, operations, providers, security, threat model, evidence, mission, release, QA and subsystem references with the live five-command Swarm contract. Final disposition requires the exact documentation PR head to pass Tooling smoke and CodeQL before merge.

## Shodan shell QA contract

Public/operator documentation must continue to agree on:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

- browser path: same-origin authenticated `POST /api/para11ax/shodan`;
- upstream origin: fixed `https://api.shodan.io`;
- credential: server-side-only `SHODAN_API_KEY`;
- no arbitrary URL/host/method/page/endpoint selection;
- no Shodan on-demand scan submission;
- `shodan download` disabled;
- search first-page only;
- host/search result arrays bounded and large raw banners removed;
- host/count/stats/info: no-query-credit classification;
- domain: consumes a query credit;
- search: may consume a query credit;
- native Shodan operator output leaves Evidence v2 / Intelligence Kernel state unchanged.

## GreyNoise Project Swarm QA contract

Public/operator documentation must continue to agree on:

```text
swarm search --from <ISO-8601> --to <ISO-8601> ...
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> ...
swarm timeseries --from <ISO-8601> --to <ISO-8601> ...
swarm export <session-id> <pcap|raw-source|raw-destination>
```

- Web-only same-origin authenticated `POST /api/para11ax/swarm`;
- upstream origin fixed to `https://api.greynoise.io` with redirects refused;
- credential server-side-only `GREYNOISE_API_KEY`;
- no arbitrary URL/host/method/header/credential/endpoint/field selection;
- explicit valid ISO-8601 ranges for search/pivots;
- query max 2,048 printable characters;
- page size max 100 and page max 10,000;
- allowlisted unique/timeseries fields; timeseries size max 100 and fixed interval set;
- JSON read result max 4 MiB; one-session binary export max 4 MiB;
- bulk `/v3/sessions/export` absent; demo export rejected locally;
- `scope=workspace` depends on the applicable Sensors entitlement; `scope=demo` depends on the applicable Swarm entitlement;
- successful read results may be explicitly captured as Investigation Workspace operator context and remain non-Evidence-v2;
- binary export does not replace current operator state or auto-attach/promote into Evidence v2.

## README/brand QA contract

README presentation is normalized to the GER1E profile README geometry while keeping PARA11AX colors/identity:

- all README panels 720px wide;
- hero `720 × 360`;
- hero primary mark 102px;
- hero rain 13px / 12px;
- panel headings 22px;
- panel body 17px;
- microtype 15px;
- terminal footer `720 × 300`;
- old 16px PARA11AX panel-body tier retired;
- footer contains `PER ASPERA AD ASTRA`;
- README text remains exact/searchable so SVG art never becomes the only documentation source.

Current asset contract is `para11ax-readme-hero-v9.svg`, `para11ax-readme-architecture-v6.svg`, `para11ax-readme-semantics-v5.svg`, and `para11ax-readme-footer-v2.svg`.

## Repository/static verification

Final candidates must run the complete repository gate:

```bash
npm ci --ignore-scripts
npm audit --omit=dev
npm run check
cd maltego
python3 -m unittest discover -s tests -v
cd ..
python3 -m compileall -q maltego
python3 -m compileall -q workers/user-scanner
```

## CI verification

### Investigation Workspace v2 pre-merge verification

The `design/investigation-workspace-v2` implementation branch completed the following local checks on 2026-09-02:

```text
Node test runner                 1,065 passed / 0 failed
Maltego unittest                66 passed / 0 failed
npm audit --omit=dev            0 vulnerabilities
Repository invariants           PASS
Public-release audit            PASS (576 tracked files)
Bash syntax                     PASS
Python compileall               PASS
Release manifest check          PASS
git diff --check                PASS
ShellCheck local                NOT AVAILABLE
```

The acceptance coverage proves canonical Investigation v2 import/export, hostile-structure rejection, compatible case/Mission migration, exact dependency invalidation, stale-report refusal, one-write serialized mutations, browser/CLI surface gates, explicit capture boundaries, no-results semantics, disposition requirements, projection-only ServiceNow output, and the complete scope-to-export analyst lifecycle. ShellCheck remains a CI proof requirement before merge; its absence from the local runner is not reported as a pass.

Authoritative CI surfaces:

- `Tooling smoke` — branch-required exact-head status; bounded Ubuntu job covering dependency audit, repository checks, Node tests, Maltego Python tests, Python compile, shell/ShellCheck and PowerShell parsing.
- `CodeQL` — separate JavaScript/TypeScript analysis, required by PARA11AX QA/release procedure.

For closure, verify the **current exact PR head** has both passing, then verify the accepted merge/main tree has fresh push runs. Do not reuse an earlier green run after the head changes.

## Deployment and live-public verification

After merge, accept production only when:

1. GitHub reports the expected exact `main` SHA.
2. Vercel production deployment metadata reports the same `githubCommitSha` and `READY` state.
3. public root/app/meta endpoints return the expected build.
4. if a release claim depends on Kernel or specialist operator runtime, authorized API output must demonstrate that exact deployed source rather than a previous READY build.

A build-rate/deployment-rate limit is a failed deployment attempt. It does not invalidate green repository CI, but it also does not make new code live.

## Credential-dependent surfaces not proven by public QA

Unless an authorized bearer/provider-secret environment is explicitly used, the following remain **not proven by public QA**:

- authenticated `/api/para11ax/health`;
- authenticated `/api/para11ax/status`;
- production provider secret configuration;
- credentialed provider enrichment health;
- User Scanner worker wiring;
- `SHODAN_API_KEY` production configuration;
- Shodan account plan/credits/rate state and production shell readiness;
- `GREYNOISE_API_KEY` production configuration;
- GreyNoise Sensors entitlement for `scope=workspace`;
- GreyNoise Swarm entitlement for `scope=demo`;
- GreyNoise workspace single-session export entitlement/readiness;
- protected live IP enrichment producing Intelligence Kernel v1.0 on the exact deployment;
- complete `para11ax providers probe --all` readiness.

Not proven is not equivalent to failed, healthy, configured, unconfigured, entitled or unentitled.

## Residual risks and deliberate gaps

- Upstream sources can be semantically wrong while syntactically valid.
- Provider/Shodan/GreyNoise coverage, quota, auth, entitlement and rate state can change independently of source.
- GreyNoise Swarm session/pivot context may be sensor-biased or stale and does not itself prove compromise/relevance/attribution.
- Explicit PCAP/raw export can contain sensitive network material and remains an analyst-controlled handling risk after download.
- Deterministic Kernel rules can still encode an imperfect analyst policy; traceability/versioning makes that reviewable rather than infallible.
- Browser-local case/investigation data is durable inside the browser profile and can be exposed by local profile compromise.
- Documentation tests protect bounded canonical facts, not every prose nuance.
- GitHub/Vercel/vendor settings are external state requiring API/settings/authorized verification when those claims matter.
- No TLS/JA3 Evidence-v2 workflow without a bounded source that passes the source gate; Swarm JA3/JA4 pivot fields remain contextual session fields, not new indicator workflows.
- No LLM, malware detonation/submission/download, credential testing, remediation, arbitrary proxying, arbitrary shell execution, Shodan on-demand scan submission, Shodan bulk `download`, arbitrary Shodan paging/endpoints, GreyNoise bulk session export/arbitrary endpoint fields, demo packet export, automatic operator-to-evidence promotion, server-side case database, or universal maliciousness score.

## Reproduction checklist

From a clean exact checkout:

```bash
npm ci --ignore-scripts
npm audit --omit=dev
npm run check
cd maltego
python3 -m unittest discover -s tests -v
cd ..
python3 -m compileall -q maltego
```

Then verify externally:

```text
GitHub exact main SHA
GitHub Tooling smoke result for that SHA
GitHub CodeQL result for that SHA
Vercel production deployment githubCommitSha + READY state
public root/app/meta HTTP behavior
```

When credential-bearing verification is authorized, run protected health/status, provider probes, User Scanner acceptance where applicable, bounded Shodan acceptance, representative IP Kernel acceptance, and GreyNoise Swarm scope acceptance appropriate to the claim. Never reinterpret missing credentials, provider errors, Shodan rate limits, depleted credits, GreyNoise entitlement errors/session absence, feed absence or Kernel projection failure as benign evidence.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
