<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Threat Model

#### Assets

- gateway bearer token and MCP OAuth authorization/access tokens;
- provider API credentials, including `SHODAN_API_KEY` and `GREYNOISE_API_KEY`;
- MCP tool catalog, routing integrity, and remote command policy;
- explicit client-carried Mission/Investigation/Case state used by MCP;
- normalized Evidence v2 and provenance;
- deterministic Scheduler/Kernel policy integrity;
- provider quotas/availability, Shodan query-credit state, and GreyNoise scope/entitlement state;
- GreyNoise Swarm session metadata and explicit packet/raw exports handled by the analyst;
- repository, CI and deployment integrity;
- analyst privacy: queried indicators/targets/session material should not leak through operational surfaces;
- browser-local case/investigation/snapshot content where the analyst chooses to persist it.

#### Adversaries and failure sources

The design assumes an untrusted caller may control indicator text, MCP tool arguments/routing headers, Shodan query text, GreyNoise Swarm query/time/session/pivot inputs and request timing; upstream providers may be malformed/compromised/unavailable; credentials can be exposed outside the application; deterministic metadata/rules can be misconfigured; browser-local or client-carried state can be mishandled; and repository/deployment supply chains can drift or be compromised.

#### Threats, controls and tests

| Threat | Primary controls | Executable evidence |
|---|---|---|
| Leaked gateway bearer or MCP access token | bearer/OAuth auth on sensitive operations; no token reflection; signed MCP tokens are scope/audience/time bound and revoked by gateway-secret rotation | auth/API/MCP/OAuth tests; public-release audit |
| OAuth redirect, client or PKCE confusion | exact ChatGPT CIMD client ID, stable redirect URI, MCP resource, scope and `S256` challenge are validated at authorization and exchange | MCP OAuth conformance and hostile-redirect tests |
| MCP method/tool confusion | `Mcp-Method` and `Mcp-Name` must agree with JSON-RPC body in current protocol profile | MCP conformance tests |
| MCP arbitrary RPC/function dispatch | fixed grouped tool catalog; explicit schemas; no caller-selected module/function | MCP catalog/tool tests |
| MCP command fallback becomes shell/admin plane | exact registered command IDs only; browser-session-only/filesystem/local-admin effects denied | MCP command-policy tests |
| MCP hidden session/cross-user state bleed | stateless transport; mission/investigation/case state explicitly supplied/returned | MCP round-trip/state tests |
| MCP bypasses underlying safety controls | tools delegate to existing bounded handlers/domain functions; no parallel provider/scanner clients | MCP handler/delegation tests plus underlying surface tests |
| Provider/Shodan/GreyNoise secret compromise | server-side-only credentials; no caller-selected headers; browser/MCP never receives vendor keys | meta/status, provider, Shodan, GreyNoise and credential-boundary tests |
| Evidence-v2 SSRF / arbitrary proxying | static provider registry; exact hosts/methods/protocols; `safeFetch`; no provider override | egress-policy/manifest tests |
| Scheduler broadens egress/admission | Provider Value Scheduler v1.0 receives only already-admitted adapters; static descriptors; `safeFetch` unchanged | scheduler/profile/orchestration/no-new-surface tests |
| Evidence-dependent source suppression | deterministic static ranking; every admitted provider remains scheduled under bounded policy | scheduler permutation/orchestration tests |
| Scheduler metadata drift | validated descriptors + deterministic fallback + capability metadata contract | provider-priority/metadata tests |
| Kernel becomes hidden active agent | Intelligence Kernel v1.0 is pure/read-only; no provider/network call, secret/env read, persistence or dependency | Kernel compatibility/no-new-surface tests |
| Kernel derived context masquerades as evidence | Evidence v2 remains authoritative; Kernel output top-level/separate; Evidence Graph/STIX isolation | evidence/kernel/graph/STIX compatibility tests |
| Kernel opaque model output | deterministic categorical rules/trace IDs; **no LLM** and no adaptive runtime learning | Kernel determinism/permutation tests |
| False independent corroboration | source-role/capability-aware diversity and typed semantics | Kernel correlation/source-diversity tests |
| Contradiction suppression | explicit contradiction severity and provider/evidence references | Kernel contradiction tests |
| Temporal fabrication | observation first/last-seen only; retrieval-only time remains unknown | Kernel temporal tests |
| Pivot over-inference | explicit normalized relationships only; stable IDs; one-hop bounded pivots; no free-text inference | Kernel relationship/pivot tests |
| Provider outage treated as benign | failed/skipped providers remain coverage state; capability-aware coverage impact | coverage/kernel tests |
| Kernel failure destroys evidence | projection exception isolated to `intelligence_projection_unavailable`; Evidence v2 preserved | orchestration isolation tests |
| User Scanner target broadening / arbitrary worker invocation | bounded email/username/category/module fields; worker destination server-configured only | User Scanner handler/parser tests |
| User Scanner hit treated as identity proof | identity semantic firewall; exact-anchor preference; independent corroboration before confirmed finding | identity workflow/docs tests and analyst gate |
| Shodan SSRF / arbitrary API proxying | exact `https://api.shodan.io` origin; six-command allowlist; validated inputs | Shodan tests |
| Shodan active-scan abuse | on-demand scan submission absent; arbitrary endpoints and `download` rejected | shell parser/handler tests |
| Shodan quota amplification | first-page search; no arbitrary paging/download; credit impact explicit | Shodan endpoint/credit tests |
| Oversized Shodan response/banner exposure | bounded search/service lists; raw banner/service bodies stripped | response-bounds tests |
| Shodan rate-limit confusion | explicit rate-limit error; no conversion to benign/empty evidence | Shodan throttling tests |
| GreyNoise Swarm SSRF / arbitrary API proxying | exact `https://api.greynoise.io` origin; six-operation grammar; no destination/method/header override | GreyNoise Swarm command/terminal/MCP tests |
| GreyNoise entitlement bypass/confusion | `scope=workspace|demo` allowlist; demo export rejected before egress; entitlement errors explicit | GreyNoise Swarm contract tests |
| GreyNoise arbitrary pivot/payload access | vetted field allowlist; fixed interval/export-type sets; unknown fields rejected | Swarm pivot/parser tests |
| GreyNoise response amplification | explicit time bounds where required; page/size/query ceilings; JSON and one-session binary cap 4 MiB; bulk export absent | Swarm bounds tests |
| GreyNoise operator result promoted as evidence | separate operator envelope; explicit investigation capture; no automatic Evidence v2/graph promotion | Swarm terminal/investigation/MCP tests |
| GreyNoise packet/raw export silently persisted | export remains explicit output; does not auto-attach to investigation | Swarm export tests |
| Redirect credential exfiltration | Evidence v2 redirects refused; Shodan host fixed; GreyNoise Swarm redirects refused | egress/Shodan/Swarm tests |
| Malicious or malformed upstream | response ceilings; parser/normalizer validation; fail-closed handling | public-feed, Shodan, Swarm, MISP and chaos tests |
| Quota/latency amplification | fixed profiles; Provider Value Scheduler v1.0; call ceilings/deadline; bounded Shodan/Swarm operations | scheduler/profile/batch/Shodan/Swarm tests |
| Provider outage / rate limiting | explicit partial failures; bounded retry/circuit behavior | scheduler/circuit/chaos tests |
| Cache poisoning / stale outage state | bounded namespaced cache; provider failures never cached | cache/chaos tests |
| Provenance confusion | parser version, retrieval time, provider, raw-result hash and Evidence v2 fingerprint preserved | Evidence v2/release-manifest tests |
| False corroboration | typed semantic classes; routing/scanner/Tor/Shodan/GreyNoise-session/certificate/ATT&CK context excluded from reputation votes | correlation semantics tests |
| False attribution | hosting/certificate/Shodan/GreyNoise-session relationships are pivots/context only; attribution requires explicit supported evidence | correlation/STIX/Evidence Graph tests |
| Ambiguous certificate/hash classification | explicit `cert-sha256:` transport | classifier/browser/Maltego tests |
| Graph over-inference | Evidence Graph uses supported explicit facts/relationships only; Kernel pivots excluded as evidence | Evidence Graph/Kernel/case graph tests |
| Guidance as hidden scoring | Guidance inherits Decision vocabulary/evidence refs; Kernel summary bounded | guidance tests |
| Browser case leakage/server persistence | IndexedDB-only browser case state; auth runtime-only; secret-bearing structural keys rejected | case storage/security/bundle tests |
| MCP client-state leakage/replay | explicit portable state; no server persistence; secret-shaped structures rejected by underlying schemas; client responsible for storage | MCP/domain import validation tests |
| Malicious MISP content | exact attribute semantics; deleted=false; bounded event fetches | MISP tests |
| Unbounded ATT&CK expansion | fixed collection IDs/type filtering; unbounded relationships omitted | TAXII tests |
| Log/telemetry leakage | allowlisted telemetry; raw indicators excluded by default; no-store count-only status | telemetry/status tests |
| STIX overclaiming | export only from gateway-generated Evidence v2; Kernel/operator conclusions excluded as new evidence | STIX/Kernel-isolation tests |
| Documentation drift | executable docs checks cover Scheduler, Kernel, provider count, API/MCP, Shodan, GreyNoise Swarm and GER1E README sizing | documentation-contract tests |
| Actions supply-chain compromise | pinned GitHub Actions; repository invariant checks | Tooling smoke |
| Deployment/source drift | production acceptance compares exact deployed SHA; credentialed surfaces verified separately | operations/QA contract |

#### MCP-specific boundary and residual risk

MCP is a transport/control plane over existing PARA11AX capabilities. It is deliberately not an arbitrary remote-code-execution surface.

The MCP server must never:

- dispatch arbitrary modules/functions selected by the caller;
- expose host-shell execution;
- expose arbitrary outbound HTTP or caller-selected provider destinations;
- expose environment-secret values or credential persistence;
- expose arbitrary filesystem paths or local-admin operations;
- silently persist Mission/Investigation/Case state server-side;
- reinterpret operator context as Evidence v2 merely because it crossed MCP;
- execute KQL or submit ServiceNow records automatically.

Residual risk remains. A stolen gateway bearer can invoke any MCP tool permitted by its fixed catalog until the bearer is rotated. A stolen OAuth access token can do the same until its expiry or gateway-secret rotation, although it is bound to the PARA11AX MCP resource and scope. Authorization codes are short-lived and PKCE-bound, but the browser/session running consent remains a trust boundary. A valid but maliciously chosen User Scanner/Shodan/Swarm target can still consume external-service resources within the bounded tool policy. Client-carried workflow state can be copied, replayed, or stored insecurely by the external MCP client. A schema or command-classification bug could expose more capability than intended, so tool-list and command-denial tests are security controls rather than documentation convenience.

The server being deployment/transport-proven does not prove a specific MCP client has been connected safely. Client installation/authentication is a separate trust boundary and proof state.

#### Provider Value Scheduler v1.0 boundary

The Scheduler is deterministic orchestration, not threat reasoning. It changes order only after fixed workflow/profile admission. Current IP reference remains 24 providers, 48-call ceiling, maximum 4 concurrent providers, maximum two attempts/provider and 20-second deadline.

The Scheduler must never:

- add a provider/host/method/protocol/credential;
- use evidence from earlier results to suppress admitted sources;
- bypass `safeFetch`;
- turn execution rank into maliciousness/confidence;
- learn/adapt from prior runtime behavior.

Missing or malformed scheduling metadata falls back deterministically.

#### Intelligence Kernel v1.0 boundary

The Kernel is deterministic derived analysis over normalized Evidence v2/correlation/coverage. It adds **no new egress** and uses **no LLM**. It does not read secrets/environment, persist data, call providers, execute KQL, or mutate authoritative evidence.

Residual risk remains: deterministic policy can still be wrong or insufficient. Controls are explicit policy/versioning, evidence fingerprints/providers, deterministic rule IDs, categorical outputs, contradiction/coverage limitations, permutation tests and guarded downstream compatibility fallbacks.

#### Shodan-specific residual risk

- Shodan can return semantically wrong, stale, or incomplete exposure data even when syntactically valid.
- An exposed service does not prove reachability, exploitability, compromise, maliciousness, ownership, or actor attribution.
- Query-credit/account policy is external and can change independently of repository source.
- Authorized search/domain use may consume credits even though the route is bounded.
- A stolen `SHODAN_API_KEY` remains usable until revoked/rotated.
- Shodan receives the operator's approved query/target because that is necessary to perform the lookup.
- MCP invocation does not change these risks or semantics; it delegates to the same bounded handler.

#### GreyNoise Project Swarm residual risk

- GreyNoise can return semantically wrong, stale, incomplete, or sensor-biased session metadata even when syntactically valid.
- Session presence, classification, tags, unique counts, timeseries buckets, JA3/JA4 values, Suricata metadata, or source/destination relationships do not by themselves prove compromise, exploitability, ownership, actor attribution, or relevance to the protected environment.
- `scope=workspace` and `scope=demo` entitlement is external account state and can change independently of repository source.
- A configured `GREYNOISE_API_KEY` does not prove Sensors entitlement, Swarm entitlement, or export capability.
- A stolen `GREYNOISE_API_KEY` remains usable until revoked/rotated.
- GreyNoise receives the approved session query/time range because that is necessary to perform the lookup.
- Workspace PCAP/raw exports can contain sensitive network material even though PARA11AX limits them to one session and 4 MiB. The analyst remains responsible for authorized handling, storage and sharing after explicit export.
- The current non-streaming fallback can read an upstream binary body before enforcing the post-read 4 MiB actual-size check when `Content-Length` is absent; the handler still rejects oversized returned data, but memory exposure is bounded by the runtime rather than a streaming pre-read cutoff. Do not overclaim a streaming receive limit.
- MCP invocation does not upgrade operator/session data to Evidence v2 or bypass entitlement checks.

#### Identity OSINT residual risk

- Exact username/email searches can return stale data, recycled handles, same-name people, scraper mirrors, or platform-generated false positives.
- Search-engine and User Scanner repetition does not become independent corroboration when results derive from the same underlying profile/page.
- A User Scanner hit is not proof of same-person identity, current account control, compromise, intent, or ownership.
- Defensive Google dorks can reveal sensitive indexed material. The workflow records the minimum evidence needed and does not harvest exposed credentials/secrets.
- New sibling accounts/domains discovered during OSINT are candidate assets, not automatic scope.
- Active User Scanner use requires authorization appropriate to the target and investigation.

#### General residual risk

- Provider APIs can return semantically wrong but syntactically valid data.
- Scheduler/Kernel rules can be internally consistent yet analytically imperfect.
- In-memory gateway cache/circuit state is instance-local and non-durable.
- Browser-local cases/investigations are durable inside the browser profile by design.
- MCP client-carried state is durable wherever the client chooses to store it; PARA11AX cannot enforce downstream client retention.
- A stolen gateway bearer remains usable until rotation; a stolen MCP OAuth access token remains usable until expiry or the same rotation.
- A compromised repository/deployment administrator can bypass application controls.
- Source coverage changes over time; absence is not benignness.
- Documentation-contract tests protect selected facts, not every prose nuance.
- Deployment quotas/rate limits can leave public production behind protected `main`.

#### Out of scope by design

LLM/adaptive threat reasoning, malware submission/detonation, remediation, credential testing, arbitrary web fetching, arbitrary shell execution, caller-controlled proxying, arbitrary MCP RPC/module dispatch, MCP local-admin/filesystem access, hidden persistent MCP workflow sessions, Shodan on-demand scan submission, Shodan bulk `download`, arbitrary Shodan paging/endpoints, GreyNoise bulk session export, arbitrary GreyNoise fields/endpoints/methods, demo packet/raw export, automatic packet/payload evidence promotion, unbounded graph crawling, server-side browser-case persistence, automated attribution and a universal maliciousness score are not PARA11AX gateway capabilities.

#### Investigation Workspace v2 threats

Investigation bundles are untrusted input. Relevant threats are prototype/accessor abuse, structural secret smuggling, oversized or sparse content, stale-state forgery, unsafe reference URLs, duplicate artifact identity, semantic promotion of operator/imported data, lost updates, misleading no-result conclusions, and unsafe downstream storage/replay of portable state. Controls are closed-schema recursive validation, byte/collection bounds, HTTPS-only references, deterministic reconstruction/status comparison, serialized atomic browser writes, explicit authority layers, dependency invalidation, explicit MCP state round-tripping, and the fixed `NO_EVIDENCE_IDENTIFIED` versus `BENIGN_EXPLAINED` distinction.

GreyNoise Swarm/User Scanner/Shodan read results follow the operator-context layer and require explicit capture semantics; packet/raw exports remain outside automatic capture. Residual risk remains analyst/client-controlled: valid state can contain incorrect analyst-supplied scope, rationale, operator context, or external results. PARA11AX preserves provenance and limitations but cannot prove the truth of operator assertions or telemetry completeness. Reports and ServiceNow records are projections only and require human approval.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
