<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Contributing

This repository is a public personal-research/lab PARA11AX project. Changes should preserve its read-only, bounded, evidence-first and deterministic design.

#### Before changing code

Read `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/EVIDENCE-SCHEMA.md`, `docs/PROVIDERS.md`, `docs/SHELL.md`, and, for GreyNoise session work, `docs/GREYNOISE-SWARM.md`.

Do not commit or add workflows that expose API keys, tokens, credentials, private keys, certificates, `.env` files, packet captures, malware samples, generated MTZ packages, or sensitive analysis material.

Do not broaden provider integrations or specialist operator routes into submission, arbitrary scanning, detonation, malware/sample download, arbitrary proxying, shell execution, secret retrieval, LLM/autonomous analysis, bulk packet/payload collection, or other write-capable behavior without an explicit security/design review.

#### Canonical analytical boundary

**Evidence v2 remains authoritative.** Provider-normalized evidence, explicit relationships, provenance and failure/coverage state are the source record.

**Provider Value Scheduler v1.0** is deterministic orchestration over already-admitted providers. A scheduler change must not silently change profile admission, provider membership, fixed hosts, credentials, methods/protocols, `safeFetch`, call ceilings or evidence semantics.

**Intelligence Kernel v1.0** is deterministic derived context. It must not create Evidence v2 observations, call providers, read secrets/environment state, add persistence/dependencies/egress, infer pivots from free text, or introduce an LLM/universal score. Evidence-backed conclusions must retain valid evidence fingerprints/providers or explicit deterministic rule IDs.

The current IP reference contract is 24 providers, 48-call ceiling, max 4 concurrent providers, maximum two attempts/provider and a 20-second deadline. Kernel relationship pivots are explicit one-hop only and failures/skips remain coverage state.

**Specialist operator context is not Evidence v2.** User Scanner, native Shodan and GreyNoise Project Swarm read results remain separate operator material. Compatible read results can be explicitly recorded by Investigation Workspace, but the capture must preserve the operator-context authority label rather than manufacturing provider evidence, corroboration, maliciousness, ATT&CK mapping or disposition. GreyNoise `swarm export` remains explicit browser download-only.

#### GreyNoise Project Swarm contract

Swarm changes must preserve the fixed Web-only boundary unless a separately reviewed design changes it:

- same-origin bearer-authenticated `/api/para11ax/swarm`;
- server-side `GREYNOISE_API_KEY`;
- fixed `https://api.greynoise.io` destination and redirect refusal;
- approved operations only: `search`, `get`, `unique`, `timeseries`, `export`;
- explicit ISO-8601 search/pivot ranges with `from < to`;
- max 2,048 printable Lucene query characters;
- page size max 100, page max 10,000;
- allowlisted pivot fields and timeseries intervals/size;
- JSON and individual single-session binary export max 4 MiB;
- no bulk `/v3/sessions/export`, arbitrary endpoint/field/method/header/credential override, or demo export;
- `scope=workspace` and `scope=demo` remain explicit upstream entitlement states, not claims inferred from a configured key;
- read results can be explicit Investigation Workspace operator context; binary export cannot silently replace/capture/promote into Evidence v2.

The canonical GreyNoise Evidence v2 IP provider and the Swarm session route are distinct surfaces and must stay documented/tested as such.

#### Development workflow

1. Branch from an up-to-date `main`.
2. Keep changes narrow and independently reviewable.
3. Preserve provider-native semantics and provenance.
4. Use TDD for behavior/contract changes: RED first, then minimal GREEN implementation.
5. When a canonical externally documented contract changes, update the relevant documentation **and** its executable drift guard in the same PR.
6. Run the repository gates before opening a ready-for-review PR.
7. Before completion, verify the exact current head rather than relying on an earlier green run.

Canonical contract changes include workflow/indicator types, provider inventory/count, scheduler policy/order/descriptors, schema/projection versions, Intelligence Kernel policy/rules, API routes, specialist operator grammar/bounds/entitlement semantics, Maltego workflow coverage, production identity, README sizing, security boundaries and release/CI claims.

```bash
npm run bootstrap
npm run verify:tooling
npm run verify:repo
npm run lint:shell
npm run check
npm test
cd maltego && python3 -m unittest discover -s tests -v
cd .. && python3 -m compileall -q maltego
```

`npm run check` includes documentation-contract tests. If one fails after a canonical contract change, fix the documentation/source mismatch; do not weaken an accurate assertion merely to preserve stale text.

#### Scheduler change requirements

A Provider Value Scheduler v1.0 change should include tests for:

- exact deterministic ranking and permutation stability;
- profile admission isolation;
- missing/malformed metadata fallback;
- provider-set/call-ceiling/concurrency/deadline invariants;
- capability metadata without credentials/internal runtime rank leakage;
- unchanged provider envelope/evidence/failure output ordering contracts where required.

If provider membership or egress changes, treat that as a separate provider/security change—not as “just scheduling.”

#### Intelligence Kernel change requirements

A Kernel change should include tests for:

- deterministic output and deep immutability;
- valid evidence-fingerprint traceability;
- source diversity/independence;
- contradictions and temporal semantics;
- explicit relationship identity / one-hop pivot bounds;
- capability-aware coverage impact;
- analyst priority/evidence strength rule behavior;
- projection failure isolation;
- Decision Support/Guidance/report compatibility fallbacks;
- Evidence Graph/STIX isolation;
- no new network, credential/env, dependency or persistence surface.

A semantic rule/policy change that can alter analyst priority or disposition requires explicit version/release consideration and regression fixtures.

#### Security review triggers

Call out a security impact explicitly when a change touches any of the following:

- authentication or authorization
- secret handling or environment variables
- outbound provider/operator hosts, redirects, headers, request construction
- provider admission or Provider Value Scheduler metadata/order
- Intelligence Kernel policy/rules, evidence traceability or relationship/pivot behavior
- User Scanner, Shodan, or GreyNoise Swarm command grammar/entitlement/credit/export semantics
- input validation/canonicalization
- response-size, timeout, retry, call-budget or rate-limit behavior
- packet/raw export or other binary handling
- cache or persistence semantics
- browser-local case/investigation storage/bundles/indexing
- Evidence Graph / Guidance / Decision Support projection semantics
- logging, Sentry, or error reflection
- GitHub Actions, dependency pinning, or deployment/bootstrap logic
- Maltego token storage, gateway transport, certificate mapping, or graph expansion
- any new provider capability beyond retrieval/enrichment

#### Pull requests

PRs should explain:

- what changed and why
- affected indicator/workflow/provider/scheduler/Kernel/operator surfaces
- RED/GREEN evidence or tests used to validate the change
- documentation-contract impact where applicable
- security/privacy/licensing/entitlement impact
- expected degraded modes, false positives or provider/telemetry limitations
- what is repository/CI-proven versus what still requires authenticated deployment/provider/vendor-entitlement verification

Prefer small PRs. Avoid drive-by formatting mixed with functional changes. If a broad QA/docs pass uncovers a runtime defect, split the behavior fix into a focused PR rather than hiding it inside documentation churn.

#### Commit messages

Use concise imperative messages. Conventional prefixes such as `feat:`, `fix:`, `chore:`, `docs:`, `test:`, and `refactor:` are preferred when they make history easier to scan.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>