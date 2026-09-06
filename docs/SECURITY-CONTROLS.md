<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Security controls

This document maps PARA11AX controls to the risks they reduce. It is descriptive, not a compliance attestation.

| Area | Control | Security effect | Residual risk |
| --- | --- | --- | --- |
| Authentication | Gateway bearer required for enrichment/health/status/User Scanner/Shodan shell/GreyNoise Swarm | Prevents unauthenticated provider-backed, operational and analyst-utility use | A stolen bearer remains usable until rotated |
| Public metadata | `/api/para11ax/meta` is static and intentionally unauthenticated | Capability/scheduler-policy discovery without credential values | Public metadata reveals product capability shape |
| Provider secrets | Vendor credentials remain server-side | Prevents browser/Maltego disclosure | Runtime compromise can still expose secrets |
| Shodan secret | `SHODAN_API_KEY` is read only server-side by provider/shell paths | Prevents analyst browser disclosure | Runtime compromise can expose the key |
| GreyNoise secret | `GREYNOISE_API_KEY` is read only server-side by provider/Swarm paths | Prevents analyst browser disclosure | Runtime compromise can expose the key |
| User Scanner secret | Optional `PARA11AX_USER_SCANNER_TOKEN` remains server-side | Prevents worker-bearer disclosure | Gateway compromise can expose it |
| Evidence input | Deterministic indicator classification and syntax/size validation | Reduces parser ambiguity and malformed-input abuse | Valid adversarial indicators still reach bounded adapters |
| Provider admission | Fixed workflow + profile admission | Caller cannot select arbitrary upstreams | Configured policy can still be imperfect |
| Provider Value Scheduler v1.0 | Static deterministic ordering among already-admitted providers; deterministic fallback | Improves bounded partial-result ordering without evidence-dependent suppression | Static priority policy can be suboptimal for some investigations |
| Scheduler metadata | Declarative authority/uniqueness/threat/pivot/latency/cost descriptors; no credential material | Makes execution policy auditable without widening provider boundary | Incorrect metadata can produce a poor but deterministic order |
| Evidence egress | Exact provider hosts/methods/protocols through `safeFetch` | Prevents arbitrary SSRF/proxying in Evidence v2 | Provider-side behavior remains an upstream risk |
| Scheduler/Kernel egress | Provider Value Scheduler v1.0 and Intelligence Kernel v1.0 add **no new egress** | Keeps deterministic orchestration/analysis inside existing trust boundary | Existing provider egress risks still apply |
| Intelligence Kernel v1.0 | Pure deterministic derived-context projection; no provider call, env/secret read, persistence or new dependency | Prevents analysis layer becoming an active network/secret/persistence surface | Deterministic policy can still be analytically imperfect |
| LLM boundary | Deterministic Scheduler/Kernel/Decision/Guidance path uses **no LLM** or adaptive runtime learning | Prevents opaque model output from becoming evidence/priority state | Human interpretation and deterministic policy errors remain possible |
| Evidence authority | Evidence v2 remains authoritative; Kernel output is derived context | Prevents derived conclusions from masquerading as provider evidence | Analysts can still over-interpret derived summaries |
| Kernel traceability | Evidence-backed conclusions retain evidence fingerprints/providers or deterministic rule IDs | Makes derived reasoning reviewable | Source evidence itself can be wrong |
| Kernel pivots | Explicit supported one-hop relationships only; free text not mined for guessed infrastructure | Limits graph/pivot over-inference | Explicit upstream relationships can still be stale/wrong |
| Kernel failure isolation | Projection failure yields explicit limitation and preserves usable Evidence v2 | Prevents analytical projection failure from destroying evidence | Analyst may lack derived context during failure |
| Capability-aware coverage | Provider capability/source-role loss classified separately from threat evidence | Prevents unavailable providers becoming false benign evidence | Capability metadata quality affects impact classification |
| User Scanner input | Only bounded email/username/category/module/boolean fields; unknown fields rejected | Prevents arbitrary worker invocation | Authorized enumeration remains noisy/third-party constrained |
| Shodan input | Fixed `host`, `search`, `count`, `stats`, `domain`, `info` grammar; validated target/query/facets | Prevents arbitrary Shodan/API invocation | Valid searches can still be expensive/broad |
| GreyNoise Swarm input | Fixed `search`, `get`, `unique`, `timeseries`, `export` grammar; bounded time/query/session/page/field/interval/type inputs | Prevents arbitrary GreyNoise/API invocation | Valid session queries can still expose sensitive network-observation context |
| Certificate identity | Explicit `cert-sha256:` transport | Prevents bare SHA-256 ambiguity | Analyst may explicitly select wrong type |
| User Scanner egress | Worker destination comes only from server configuration | Contains high-fan-out active OSINT behind one controlled boundary | Worker intentionally contacts many third parties |
| Shodan egress | Shell origin fixed to `https://api.shodan.io`; no caller-selected URL/host/method/proxy | Prevents Shodan shell becoming generic proxy | Shodan remains an external dependency |
| GreyNoise Swarm egress | Swarm origin fixed to `https://api.greynoise.io`; no caller-selected destination/method/header/credential | Prevents Swarm route becoming a generic proxy | GreyNoise remains an external dependency |
| Shodan operation scope | No on-demand scan submission, arbitrary paging, bulk `download`, or arbitrary endpoint selection | Limits quota/resource amplification and active behavior | Approved search/domain may consume query credits |
| GreyNoise Swarm operation scope | No arbitrary fields, bulk session export, demo export, caller-selected endpoints, or unbounded packet retrieval | Limits data amplification and entitlement bypass | Approved workspace exports can still contain sensitive packet/raw material |
| Shodan response bounds | First-page search, capped match/service arrays, large banners removed | Limits response amplification/excess raw data | Bounded metadata can still be sensitive in investigations |
| GreyNoise Swarm response bounds | JSON and individual binary export capped at 4 MiB; bounded structural sanitization; one session/export | Limits response/data amplification | A bounded PCAP/raw export can still contain sensitive content |
| Provider handling | Timeouts, bounded bodies, structured 429 handling | Limits resource exhaustion and uncontrolled upstream behavior | Provider outage can produce partial results |
| Error handling | Raw upstream exception text/credential-bearing URLs not reflected | Reduces secret/internal leakage | Logs still require safe handling |
| Evidence semantics | Provider-native semantics and provenance preserved | Reduces false certainty and naive vendor voting | Analysts can over-interpret correlations |
| Shodan semantics | Service/exposure observations remain context; shell output leaves Evidence v2/Kernel unchanged | Prevents exposure becoming maliciousness/attribution/case evidence | Manual over-correlation remains possible |
| GreyNoise Swarm semantics | Session/pivot read results are operator context; explicit capture does not promote them into Evidence v2 | Prevents session presence/count/trend becoming automatic maliciousness/attribution evidence | Analysts can still over-interpret session context manually |
| Identity semantics | User Scanner results remain separate from Evidence v2/Kernel | Prevents handle hits becoming threat/identity proof | Manual over-correlation remains possible |
| Evidence Graph | Explicit deterministic bounded facts/relationships only; Kernel pivots excluded as evidence | Prevents free-form/derived graph inference | Explicit upstream relationships can still be wrong |
| Guidance | Inherits Decision vocabulary/evidence validation; Kernel summary bounded | Prevents a second hidden scoring engine or raw Kernel leakage | Analysts can over-weight guidance |
| Attribution | Infrastructure/certificate/Shodan/GreyNoise-session proximity is not actor attribution | Reduces unsupported attribution | Human judgment remains a risk |
| Browser cases | IndexedDB-only case persistence; active case/auth runtime-only | Prevents server-side IOC history/bearer persistence | Local browser compromise can expose cases |
| Browser utilities | User Scanner/Shodan/Swarm output not automatically persisted as typed Evidence v2 case material | Prevents untyped utility results entering case evidence | Analysts can explicitly capture contextual operator records or copy/export data |
| HTTP response | Authenticated responses use defensive headers/no-store where applicable | Reduces accidental caching/exposure | Downstream clients can persist data |
| Deployment | Production acceptance compares deployment metadata to exact verified `main` SHA | Reduces stale/unreviewed deployment acceptance | Build quota/rate limits can leave production behind source |
| CI supply chain | Actions pinned to immutable SHAs; bounded Tooling smoke + CodeQL | Reduces mutable-action and drift risk | Pinned dependencies can later be vulnerable |
| Repository hygiene | Secrets/captures/samples/generated sensitive artifacts blocked/ignored | Reduces accidental publication | Ignore rules do not remove history |
| Public release | `npm run audit:public` plus release checklist | Adds publication guardrail | Not complete DLP/licensing review |
| Documentation integrity | Executable documentation/GER1E sizing/Scheduler/Kernel/Shodan/Swarm contract tests | Reduces silent public-doc drift | Prose nuance still requires review |

#### Intelligence Kernel v1.0 security boundary

Intelligence Kernel v1.0 is deterministic derived analysis over already-normalized evidence, relationships, correlation and coverage. It adds no new egress and uses no LLM. It does not read provider secrets/environment state, perform persistence, call arbitrary tools, fetch URLs or create Evidence v2 observations.

Security/semantic invariants:

- Evidence v2 remains authoritative.
- failed/skipped/missing providers remain coverage state, not negative or benign evidence;
- observation timestamps, not retrieval timestamps, drive temporal relevance;
- contradictions stay explicit;
- explicit one-hop pivots retain evidence/provider provenance;
- free text cannot manufacture relationship candidates;
- Kernel-derived relationships do not become Evidence Graph evidence edges;
- STIX does not promote Kernel conclusions into new evidence/attribution objects;
- Decision Support uses a guarded compatibility check and retains legacy fallback;
- Guidance receives only a bounded summary with existing evidence-reference validation;
- projection failure is isolated as an explicit limitation.

#### Provider Value Scheduler v1.0 security boundary

The Scheduler is an orchestration policy, not an analytical engine. It operates only on already-admitted adapters and does not alter `safeFetch` host/method/protocol controls. The current IP reference remains 24 providers / 48-call ceiling, max concurrency 4, maximum two attempts/provider, 20-second deadline. Returned evidence cannot suppress later admitted providers.

#### Shodan analyst-shell boundary

The native Shodan command surface is an explicit analyst utility, not a general-purpose shell and not a caller-controlled proxy. The browser calls only same-origin `POST /api/para11ax/shodan`; the gateway authenticates the request, validates one of six approved commands, reads `SHODAN_API_KEY` server-side, and contacts only `https://api.shodan.io`.

Approved commands:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

`shodan download`, arbitrary paging/URLs, unsupported options, caller-selected methods and on-demand scan submission are disabled. Search is first-page only and normalized output is bounded. Large raw banners are omitted.

Credit impact is explicit: host/count/stats/info are no-query-credit operations; domain consumes a query credit; search may consume a query credit depending on Shodan plan/query behavior.

Shodan service/exposure metadata is contextual. Native shell output is not automatically injected into Evidence v2 correlation, Intelligence Kernel, Decision Support, Evidence Graph, case graph, STIX or case evidence.

#### GreyNoise Project Swarm boundary

GreyNoise Swarm is an explicit Web-only analyst utility beside the canonical GreyNoise Evidence v2 IP provider. The browser calls only same-origin `POST /api/para11ax/swarm`; the gateway authenticates the request, validates one of five approved operations, reads `GREYNOISE_API_KEY` server-side, and contacts only `https://api.greynoise.io` with redirects refused.

Approved command families are:

```text
swarm search --from <ISO-8601> --to <ISO-8601> ...
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> ...
swarm timeseries --from <ISO-8601> --to <ISO-8601> ...
swarm export <session-id> <pcap|raw-source|raw-destination>
```

The route rejects unknown fields, malformed/oversized bodies, invalid ranges, unsafe session IDs, non-allowlisted pivot fields, unsupported intervals/export types, caller-selected URLs/methods/headers/credentials, bulk export and demo export. Search page size is capped at 100, page number at 10,000, query at 2,048 printable characters, timeseries size at 100, and JSON/binary responses at 4 MiB.

`scope=workspace` and `scope=demo` are passed only after local validation. Workspace session access depends on the applicable Sensors entitlement; demo access depends on the applicable Swarm entitlement. The presence of a configured `GREYNOISE_API_KEY` does not prove entitlement.

Successful read operations (`search`, `get`, `unique`, `timeseries`) can become the current bounded operator result. `investigation capture operator` can explicitly record compatible read context, but that capture never becomes Evidence v2, provider corroboration, ATT&CK mapping, maliciousness, or analyst disposition. `swarm export` is an explicit browser download, never replaces the current operator result, and is not automatically attached to the investigation/evidence graph.

#### User Scanner active OSINT boundary

User Scanner remains an explicitly active OSINT capability. The PARA11AX shell calls a same-origin authenticated route which forwards only to the server-configured isolated worker. Browser callers cannot set worker URL/token, proxy routes, concurrency, or arbitrary destinations. Matching handles/registration signals are platform-specific OSINT, not same-person identity proof or compromise evidence.

#### External settings controls

The following require GitHub/Vercel/account settings and cannot be guaranteed by repository files alone:

- branch/ruleset protection for `main`;
- force-push/deletion restrictions;
- required status checks/reviews;
- signed-commit enforcement where practical;
- secret scanning/push protection;
- CodeQL/default code scanning;
- passkey/2FA/recovery hygiene;
- production environment-secret configuration including `SHODAN_API_KEY`, `GREYNOISE_API_KEY` and User Scanner wiring;
- GreyNoise account Sensors/Swarm entitlement for the exact scope/operation being claimed.

A Vercel `READY` deployment proves deployment/source identity only. Provider credential readiness, User Scanner wiring, authenticated Kernel output, Shodan shell readiness, GreyNoise Swarm scope entitlement and export readiness require authorized checks on that exact deployment.

## Investigation Workspace controls

- Canonical imports reject unknown keys, unsupported versions, inherited/accessor/sparse structures, non-finite values, secret-shaped structural keys, unsafe URLs, invalid timestamps, duplicate identities, forged status projections, and bundles over 4 MiB.
- Browser persistence stays in the existing local IndexedDB boundary. Active investigation identity is runtime-only; no server persistence, credential storage, or new network path is introduced.
- Repository mutations are serialized. Validation and derivation occur on a detached candidate; successful mutations write once, while failures perform no write.
- Evidence, operator context, imported results, analyst disposition, reports, and ServiceNow projections retain explicit authority labels. GreyNoise Swarm read context follows the same operator-context layer; PCAP/raw exports remain outside automatic capture. No automatic evidence promotion, ticket submission, KQL execution, or severity assignment occurs.
- Dependency fingerprints and stable invalidation reasons prevent stale hunt, result, disposition, report, or ServiceNow artifacts from satisfying current readiness gates.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>