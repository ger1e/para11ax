<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Security policy

This repository is public. PARA11AX is a provenance-first, read-only CTI enrichment/correlation core with deterministic analytical projections and bounded analyst-operations surfaces for personal research/lab use. Every commit, pull request, workflow artifact, issue, and release must be treated as potentially public information.

#### Supported use

Do not route commercial-client, internal-enterprise, restricted, or otherwise sensitive data through providers or analyst utilities unless licensing/data-handling terms and authorization have been explicitly reviewed. Provider, Shodan and GreyNoise Swarm data are evidence/context according to their specific source semantics, not automatic attribution.

#### Secrets

- Never commit API keys, tokens, credentials, private keys, certificates, `.env` files, packet captures, malware samples, or sensitive analysis artifacts.
- Use Vercel/project environment secrets for production and `.env.example` only as a non-secret template.
- The only credential a Maltego client should know is `PARA11AX_TOKEN`; vendor credentials remain server-side.
- `SHODAN_API_KEY` and `GREYNOISE_API_KEY` are server-side only. They must never appear in browser JavaScript, terminal output, docs examples, screenshots, logs, or committed files.
- API/health/status/meta responses must never return environment-variable values.
- Provider/Shodan/GreyNoise errors must not reflect credential-bearing URLs, headers, arbitrary upstream exception text, or secrets.
- Unexpected telemetry must remain correlation-only and exclude request bodies, raw indicators/identity targets/Swarm payloads, stack traces and credentials.
- If a secret is exposed, revoke/rotate it first, then remove it from repository history as needed.

#### Application boundary

- Evidence v2 provider integrations are retrieval/enrichment only unless explicitly documented otherwise.
- Do not add malware submission, detonation, sample download, takedown, credential testing, arbitrary HTTP proxying, arbitrary outbound headers, shell execution, secret-read/list endpoints, autonomous remediation, or LLM-driven autonomous analysis without explicit design/security review.
- Provider endpoints remain fixed and indicator input never controls the outbound host.
- Specialist operator routes remain fixed-destination, grammar-limited surfaces rather than generic network clients.
- Missing provider credentials degrade to skipped/partial coverage rather than unsafe fallback.
- Preserve provider semantics; absence is not benign evidence; infrastructure/session proximity is not actor attribution.

#### Provider Value Scheduler v1.0 boundary

Provider Value Scheduler v1.0 deterministically orders providers only **after** fixed workflow/profile admission. It does not change provider membership, credentials, hosts, methods, protocols, `safeFetch`, or Evidence v2 semantics.

Current IP reference invariants are 24 providers, 48-call ceiling (maximum two attempts/provider), max concurrency 4 and 20-second deadline. Every admitted provider remains scheduled; returned evidence cannot suppress later providers. Missing/invalid scheduling descriptors fall back deterministically.

Scheduler metadata is orchestration policy, not threat evidence or a maliciousness score.

#### Intelligence Kernel v1.0 boundary

Intelligence Kernel v1.0 is a pure deterministic derived-context projection over normalized Evidence v2, explicit relationships, correlation and coverage. **Evidence v2 remains authoritative.** Kernel output never becomes a provider observation simply because it is useful analyst context.

Security invariants:

- the Kernel adds **no new egress**;
- it performs no provider call or arbitrary network access;
- it reads no provider secret/environment credential state;
- it adds no persistence or dependency surface;
- it uses **no LLM**, adaptive runtime model or learning loop;
- evidence-backed conclusions retain evidence fingerprints/providers or deterministic rule IDs;
- provider failures/skips remain coverage state, never benign/negative threat evidence;
- temporal relevance uses observation timestamps; missing time remains unknown;
- relationships/pivots come only from supported explicit normalized relationships and are bounded to one hop;
- free text is not mined to invent related infrastructure;
- contradictions remain explicit;
- Kernel-derived pivots do not become Evidence Graph evidence edges or unsupported STIX/attribution facts;
- projection failure is isolated as `intelligence_projection_unavailable` and must not destroy otherwise-valid Evidence v2.

Decision Support consumes only a compatible Kernel version/type and retains the legacy deterministic fallback otherwise. Guidance can expose only a bounded Kernel summary while existing Evidence Graph/evidence-fingerprint validation remains authoritative.

#### Native Shodan analyst-shell boundary

PARA11AX exposes six bounded native Shodan commands:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

The browser calls only same-origin `POST /api/para11ax/shodan`. The gateway validates command/arguments, reads `SHODAN_API_KEY` server-side, and contacts only fixed `https://api.shodan.io`.

Security invariants:

- no caller-selected URL/host/method/credential/proxy;
- no arbitrary endpoint/paging;
- search first-page only;
- response arrays bounded and large raw banner/service bodies removed;
- `shodan download` disabled;
- on-demand Shodan scan submission absent;
- missing configuration fails closed;
- 429/rate-limit state remains explicit;
- Shodan operator output is not automatically converted into Evidence v2, Intelligence Kernel input, case evidence, STIX, Evidence Graph, Guidance, reputation voting, or attribution.

Credit impact is explicit. Host/count/stats/info are no-query-credit operations; domain consumes a query credit; search may consume a query credit depending on plan/query behavior.

A Shodan-visible port/service/product/tag/DNS record is infrastructure/exposure context only. It does not by itself prove exploitability, compromise, maliciousness, ownership, current reachability, or attribution.

#### GreyNoise Project Swarm boundary

GreyNoise Swarm is a separate **WEB ONLY** operator surface beside the canonical GreyNoise Evidence v2 IP provider. The browser calls only same-origin `POST /api/para11ax/swarm`; the gateway validates one of five approved operations, reads `GREYNOISE_API_KEY` server-side, and contacts only fixed `https://api.greynoise.io` with redirects refused.

```text
swarm search --from <ISO-8601> --to <ISO-8601> ...
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> ...
swarm timeseries --from <ISO-8601> --to <ISO-8601> ...
swarm export <session-id> <pcap|raw-source|raw-destination>
```

Security invariants:

- no caller-selected URL/host/method/header/credential/proxy;
- no arbitrary endpoint, bulk `/v3/sessions/export`, or arbitrary pivot field;
- search/pivot ranges require valid explicit ISO-8601 `from < to` bounds;
- query text is capped at 2,048 printable characters;
- search page size is capped at 100 and page number at 10,000;
- timeseries size is capped at 100 and interval is a fixed allowlist;
- JSON results and single-session PCAP/raw exports are capped at 4 MiB;
- `scope=demo` export is rejected before egress;
- missing configuration, authentication/entitlement rejection, rate limiting, missing session, timeout, malformed/oversized response and transport failure stay explicit operational errors;
- `search`, `get`, `unique` and `timeseries` output may be explicitly captured as Investigation Workspace operator context but is never automatically converted into Evidence v2, Intelligence Kernel input, corroboration, ATT&CK mapping, disposition, STIX or Evidence Graph evidence;
- `swarm export` is explicit browser download-only and does not replace the current operator result or auto-attach to an investigation.

`scope=workspace` depends on the applicable upstream Sensors entitlement. `scope=demo` depends on the applicable Swarm entitlement. A configured `GREYNOISE_API_KEY` does not prove either entitlement or workspace export capability.

Swarm session metadata, classification, tags, JA3/JA4, Suricata fields, counts/trends and packet/raw data remain contextual observations. They do not by themselves prove exploitability, compromise, ownership, relevance to a protected environment or attribution. Explicit packet/raw downloads require authorized handling and storage by the analyst.

#### User Scanner boundary

User Scanner remains a separate active-OSINT capability. The browser calls same-origin `/api/para11ax/user-scanner`; the gateway forwards only to `PARA11AX_USER_SCANNER_URL` with optional server-side `PARA11AX_USER_SCANNER_TOKEN`. Callers cannot select worker URL, proxy, concurrency, timeout, or arbitrary destination. Account/handle matches are not same-person identity proof or compromise evidence and are not Intelligence Kernel input.

#### Evidence, graph and guidance boundary

- Evidence v2 is the authoritative normalized source record.
- Intelligence Kernel v1.0 is deterministic derived context and does not create Evidence v2 facts.
- Evidence Graph v1.0 is built from supported explicit Evidence v2 facts/relationships; Kernel-derived relationships are excluded as evidence.
- Guidance v1.0 inherits the bounded Decision Support vocabulary/evidence references and can carry only bounded Kernel summary fields.
- No universal threat/risk score is introduced.
- User Scanner, Shodan shell and GreyNoise Swarm read output remain operator context. Explicit Investigation Workspace operator capture preserves that authority label instead of promoting the material into Evidence v2.

#### Browser-local case and investigation boundary

- Case/investigation persistence is browser-local IndexedDB, not server-side IOC storage.
- Active case/investigation selection and gateway authentication remain runtime-only.
- Case notes/diff prose must not be parsed into graph entities.
- Case/index/graph/investigation modules must not introduce direct network persistence paths.
- Export/import bundles remain bounded, typed, and secret-key screened.
- User Scanner/Shodan/Swarm output is not automatically persisted as Evidence v2 case material; compatible read context requires explicit `investigation capture operator`.
- Swarm binary export remains outside automatic capture.

#### API and error boundary

Bearer-protected private routes include:

- `POST /api/para11ax/enrich`
- `POST /api/para11ax/batch`
- `POST /api/para11ax/stix`
- `POST /api/para11ax/user-scanner`
- `POST /api/para11ax/shodan`
- `POST /api/para11ax/swarm`
- `GET /api/para11ax/health`
- `GET /api/para11ax/status`

`GET /api/para11ax/meta` is intentionally public static metadata. Explicit non-JSON request content types are rejected where JSON is required. Inputs are bounded before external calls. Authenticated operational responses use defensive headers/no-store as applicable. Gateway bearer comparison remains constant-time. Unknown `/api/para11ax/*` routes fail closed.

#### Reporting boundary

Reports compile only from bounded frozen gateway/investigation snapshots and must not perform provider/User Scanner/Shodan/GreyNoise Swarm calls. The IP analyst report can consume Kernel-derived context from the snapshot but cannot perform browser-side re-reasoning that manufactures evidence. Operator context retains its separate authority label. Snapshot secret scanning and report quality gates remain mandatory. KQL is an analyst artifact, not an execution channel. Artifact manifests retain deterministic SHA-256 digests.

#### Maltego

Remote gateway URLs must use HTTPS except localhost development. Redirects are refused by the local gateway client. Local credential storage uses platform-appropriate secure storage. Generated `.mtz` packages remain untracked local artifacts.

Shodan analyst-shell commands, GreyNoise Swarm session operations and Kernel pivot candidates are not silently converted into new Maltego Evidence v2 transforms.

#### Supply chain and governance

- GitHub Actions must remain pinned to immutable commit SHAs.
- Runtime parity is Node.js 24.x across Vercel, CI, Codespaces, and local bootstrap flows.
- `package-lock.json` is mandatory; CI uses deterministic install/audit.
- `Tooling smoke` validates repository invariants, Node tests, Maltego tests, Python compilation, shell/ShellCheck, and PowerShell syntax. CodeQL runs separately.
- Protected `main` must use exact-head status checks and deployment/source identity verification.
- Repository files describe governance intent but do not prove current external GitHub/Vercel/vendor-account settings.

#### Validation

Run before accepting changes:

```bash
npm run check
npm run verify:deps
npm run verify:tooling
cd maltego && python3 -m unittest discover -s tests -v
cd .. && python3 -m compileall -q maltego
```

Authenticated production acceptance should additionally verify the exact deployed SHA and, when authorized, protected health/status, representative Evidence v2 enrichment, expected IP Intelligence Kernel v1.0 output, User Scanner wiring, Shodan shell wiring using a no-query-credit command where possible, and a bounded GreyNoise Swarm read for each scope whose entitlement is being claimed. Validate workspace export only when intentionally authorized.

A public READY deployment does not itself prove provider secrets, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, GreyNoise Sensors/Swarm entitlement, User Scanner worker readiness, or that a newer repository-only feature is live. A Vercel deployment/build-rate limit means production remains on the previous READY source until a later exact-SHA deployment succeeds.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>