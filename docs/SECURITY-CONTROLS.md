<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Security controls

This document maps PARA11AX controls to the risks they reduce. It is descriptive, not a compliance attestation.

| Area | Control | Security effect | Residual risk |
| --- | --- | --- | --- |
| Authentication | OAuth 2.1/PKCE or gateway bearer required for MCP tool execution; gateway bearer required for protected REST operations | Prevents unauthenticated provider-backed, operational and analyst-utility use | A stolen access token remains usable until expiry or gateway-secret rotation |
| MCP OAuth | Fixed ChatGPT CIMD client/redirect, exact resource and scope, `S256` PKCE, short-lived signed codes, time/audience/scope-bound access tokens | Lets ChatGPT link without receiving the reusable gateway secret | Compromise of the authorization browser session or an unexpired access token still permits bounded tool use |
| MCP transport | `/mcp` is explicit POST-only stateless route; modern `Mcp-Method` and `Mcp-Name` must agree with JSON-RPC body | Prevents ambiguous/misdirected remote tool dispatch | A correctly authenticated malicious caller can still invoke allowed tools within their policy |
| MCP capability boundary | Fixed grouped tool catalog delegates to existing handlers; no arbitrary function/module dispatch | Prevents MCP becoming a generic RPC execution plane | Tool schemas/policies can still contain design defects |
| MCP command fallback | `para11ax_command` resolves exact registered command IDs and denies browser-session-only, filesystem and local-admin effects | Preserves broad functional parity without exposing host shell/admin primitives | Safe-command classification must remain accurate |
| MCP state | Mission/investigation/case state is explicit state-in/state-out; no hidden cross-user server session | Reduces session confusion, cross-user state bleed and server-side analyst-data persistence | Client-side state can still be mishandled or replayed |
| Public metadata | `/api/para11ax/meta` is static and intentionally unauthenticated | Capability discovery without credential values | Public metadata reveals limited product capability shape |
| Provider secrets | Vendor credentials remain server-side | Prevents browser/Maltego/MCP disclosure | Runtime compromise can still expose secrets |
| Shodan secret | `SHODAN_API_KEY` is read only server-side by provider/operator paths | Prevents analyst client disclosure | Runtime compromise can expose the key |
| GreyNoise secret | `GREYNOISE_API_KEY` is read only server-side by provider/Swarm paths | Prevents analyst client disclosure | Runtime compromise can expose the key |
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
| GreyNoise Swarm input | Fixed `search`, `get`, `unique`, `timeseries`, `diff`, `export` grammar; bounded time/query/session/page/field/interval/type inputs | Prevents arbitrary GreyNoise/API invocation | Valid session queries can still expose sensitive network-observation context |
| Certificate identity | Explicit `cert-sha256:` transport | Prevents bare SHA-256 ambiguity | Analyst may explicitly select wrong type |
| User Scanner egress | Worker destination comes only from server configuration | Contains high-fan-out active OSINT behind one controlled boundary | Worker intentionally contacts many third parties |
| Shodan egress | Origin fixed to `https://api.shodan.io`; no caller-selected URL/host/method/proxy | Prevents Shodan surface becoming generic proxy | Shodan remains an external dependency |
| GreyNoise Swarm egress | Swarm origin fixed to `https://api.greynoise.io`; no caller-selected destination/method/header/credential | Prevents Swarm route becoming a generic proxy | GreyNoise remains an external dependency |
| Shodan operation scope | No on-demand scan submission, arbitrary paging, bulk `download`, or arbitrary endpoint selection | Limits quota/resource amplification and active behavior | Approved search/domain may consume query credits |
| GreyNoise Swarm operation scope | No arbitrary fields, bulk session export, demo export, caller-selected endpoints, or unbounded packet retrieval | Limits data amplification and entitlement bypass | Approved workspace exports can still contain sensitive packet/raw material |
| Shodan response bounds | First-page search, capped match/service arrays, large banners removed | Limits response amplification/excess raw data | Bounded metadata can still be sensitive in investigations |
| GreyNoise Swarm response bounds | JSON and individual binary export capped at 4 MiB; bounded structural sanitization; one session/export | Limits response/data amplification | A bounded PCAP/raw export can still contain sensitive content |
| Provider handling | Timeouts, bounded bodies, structured 429 handling | Limits resource exhaustion and uncontrolled upstream behavior | Provider outage can produce partial results |
| Error handling | Raw upstream exception text/credential-bearing URLs not reflected | Reduces secret/internal leakage | Logs still require safe handling |
| Evidence semantics | Provider-native semantics and provenance preserved | Reduces false certainty and naive vendor voting | Analysts can over-interpret correlations |
| Shodan semantics | Service/exposure observations remain context; output leaves Evidence v2/Kernel unchanged | Prevents exposure becoming maliciousness/attribution/case evidence | Manual over-correlation remains possible |
| GreyNoise Swarm semantics | Session/pivot read results are operator context; explicit capture does not promote them into Evidence v2 | Prevents session presence/count/trend becoming automatic maliciousness/attribution evidence | Analysts can still over-interpret session context manually |
| Identity semantics | Google dork/User Scanner results remain leads/operator context until independently corroborated; separate from Evidence v2/Kernel | Prevents indexed/account hits becoming identity/threat proof | Manual over-correlation remains possible |
| Evidence Graph | Explicit deterministic bounded facts/relationships only; Kernel pivots excluded as evidence | Prevents free-form/derived graph inference | Explicit upstream relationships can still be wrong |
| Guidance | Inherits Decision vocabulary/evidence validation; Kernel summary bounded | Prevents a second hidden scoring engine or raw Kernel leakage | Analysts can over-weight guidance |
| Attribution | Infrastructure/certificate/Shodan/GreyNoise-session proximity is not actor attribution | Reduces unsupported attribution | Human judgment remains a risk |
| Browser cases | IndexedDB-only case persistence; active case/auth runtime-only | Prevents server-side IOC history/bearer persistence | Local browser compromise can expose cases |
| Browser/MCP utilities | User Scanner/Shodan/Swarm output not automatically persisted/promoted as typed Evidence v2 case material | Prevents untyped utility results entering case evidence | Analysts can explicitly capture contextual records or copy/export data |
| HTTP response | Authenticated responses use defensive headers/no-store where applicable | Reduces accidental caching/exposure | Downstream clients can persist data |
| Deployment | Production acceptance compares deployment metadata to exact verified `main` SHA | Reduces stale/unreviewed deployment acceptance | Build quota/rate limits can leave production behind source |
| CI supply chain | Actions pinned to immutable SHAs; bounded Tooling smoke + CodeQL | Reduces mutable-action and drift risk | Pinned dependencies can later be vulnerable |
| Repository hygiene | Secrets/captures/samples/generated sensitive artifacts blocked/ignored | Reduces accidental publication | Ignore rules do not remove history |
| Public release | `npm run audit:public` plus release checklist | Adds publication guardrail | Not complete DLP/licensing review |
| Documentation integrity | Executable documentation/GER1E sizing/Scheduler/Kernel/MCP/Shodan/Swarm contract tests | Reduces silent public-doc drift | Prose nuance still requires review |

#### MCP remote-control boundary

MCP is a transport/control-plane layer over existing PARA11AX capabilities, not a new evidence provider and not a privileged bypass around the gateway.

Security invariants:

- protocol initialization and tool metadata discovery execute no capability and remain public;
- every MCP tool declares the `para11ax:use` OAuth scope;
- tool execution requires a validated resource-bound OAuth token or the same gateway bearer as other protected remote operations;
- OAuth discovery, `WWW-Authenticate`, and tool-level `mcp/www_authenticate` challenges identify the protected resource;
- the modern protocol uses `MCP-Protocol-Version: 2026-07-28`;
- `Mcp-Method` must match the JSON-RPC method;
- `Mcp-Name` must match `params.name` for `tools/call`;
- the server exposes a fixed grouped tool registry rather than arbitrary module/function dispatch;
- tool implementations reuse existing bounded handlers/domain functions;
- `para11ax_command` accepts exact registered command IDs only and denies browser-session-only, filesystem and local-admin effects;
- no arbitrary shell, arbitrary outbound HTTP, arbitrary filesystem path, environment-secret read, credential persistence, automatic KQL execution, or automatic ServiceNow submission is exposed;
- mission/investigation/case state is explicit client-carried state, not a hidden server-side session;
- an MCP result retains the authority class of the underlying capability: operator context remains operator context, Evidence v2 remains Evidence v2, and derived context remains derived context.

The MCP route being live does not prove that a particular external client is connected or that every credentialed dependency is configured. Treat MCP transport verification, client connection, and provider/worker/entitlement readiness as separate proof states.

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

#### Shodan analyst boundary

The native Shodan surface is an explicit analyst utility, not a general-purpose shell and not a caller-controlled proxy. Web/REST/MCP paths delegate to the same bounded handler; the gateway authenticates the request, validates one of six approved commands, reads `SHODAN_API_KEY` server-side, and contacts only `https://api.shodan.io`.

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

Shodan service/exposure metadata is contextual. Output is not automatically injected into Evidence v2 correlation, Intelligence Kernel, Decision Support, Evidence Graph, case graph, STIX or case evidence.

#### GreyNoise Project Swarm boundary

GreyNoise Swarm is an explicit analyst utility beside the canonical GreyNoise Evidence v2 IP provider. Web/REST/MCP paths delegate to the same bounded handler; the gateway authenticates the request, validates the approved operations, reads `GREYNOISE_API_KEY` server-side, and contacts only `https://api.greynoise.io` with redirects refused.

Approved command families are:

```text
swarm search --from <ISO-8601> --to <ISO-8601> ...
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> ...
swarm timeseries --from <ISO-8601> --to <ISO-8601> ...
swarm diff --query <GNQL> ...
swarm export <session-id> <pcap|raw-source|raw-destination>
```

The handler rejects unknown fields, malformed/oversized bodies, invalid ranges, unsafe session IDs, non-allowlisted pivot fields, unsupported intervals/export types, caller-selected URLs/methods/headers/credentials, bulk export and demo export. Search page size is capped at 100, page number at 10,000, query at 2,048 printable characters, timeseries size at 100, and JSON/binary responses at 4 MiB.

`scope=workspace` and `scope=demo` are passed only after local validation. Workspace session access depends on the applicable Sensors entitlement; demo access depends on the applicable Swarm entitlement. The presence of a configured `GREYNOISE_API_KEY` does not prove entitlement.

Successful read operations can become bounded operator context. Explicit investigation capture never becomes Evidence v2, provider corroboration, ATT&CK mapping, maliciousness, or analyst disposition. `swarm export` remains explicit output and is not automatically attached to the investigation/evidence graph.

#### User Scanner active OSINT boundary

User Scanner remains an explicitly active OSINT capability. REST/Web/MCP calls forward only through the server-configured isolated worker after bounded validation. Callers cannot set worker URL/token, proxy routes, concurrency, or arbitrary destinations. Matching handles/registration signals are platform-specific OSINT, not same-person identity proof or compromise evidence.

The preferred identity route is exact authorised identifier -> defensive Google dorking/passive discovery -> User Scanner -> collision rejection -> independent corroboration -> explicit operator-context capture. See `IDENTITY-OSINT.md` and `GOOGLE-DORKING.md`.

#### External settings controls

The following require GitHub/Vercel/account/client settings and cannot be guaranteed by repository files alone:

- branch/ruleset protection for `main`;
- force-push/deletion restrictions;
- required status checks/reviews;
- signed-commit enforcement where practical;
- secret scanning/push protection;
- CodeQL/default code scanning;
- passkey/2FA/recovery hygiene;
- production environment-secret configuration including `PARA11AX_TOKEN`, `SHODAN_API_KEY`, `GREYNOISE_API_KEY` and User Scanner wiring;
- GreyNoise account Sensors/Swarm entitlement for the exact scope/operation being claimed;
- external MCP client/plugin installation and secure bearer/authentication configuration.

A Vercel `READY` deployment proves deployment/source identity only. Provider credential readiness, User Scanner wiring, authenticated Kernel output, Shodan readiness, GreyNoise Swarm scope entitlement/export readiness, and external MCP-client connectivity require authorized checks on that exact deployment.

## Investigation Workspace controls

- Canonical imports reject unknown keys, unsupported versions, inherited/accessor/sparse structures, non-finite values, secret-shaped structural keys, unsafe URLs, invalid timestamps, duplicate identities, forged status projections, and bundles over 4 MiB.
- Browser persistence stays in the existing local IndexedDB boundary. Active investigation identity is runtime-only; no server persistence, credential storage, or new network path is introduced.
- MCP operates on explicit portable investigation/case/mission state; the server does not persist hidden cross-user workflow state.
- Repository mutations are serialized. Validation and derivation occur on a detached candidate; successful mutations write once, while failures perform no write.
- Evidence, operator context, imported results, analyst disposition, reports, and ServiceNow projections retain explicit authority labels. GreyNoise Swarm read context follows the same operator-context layer; PCAP/raw exports remain outside automatic capture. No automatic evidence promotion, ticket submission, KQL execution, or severity assignment occurs.
- Dependency fingerprints and stable invalidation reasons prevent stale hunt, result, disposition, report, or ServiceNow artifacts from satisfying current readiness gates.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
