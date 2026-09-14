<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### PARA11AX Architecture

#### Purpose

PARA11AX is a provenance-first CTI enrichment/correlation core plus bounded analyst-operations surface for defensive research. The canonical Evidence v2 core accepts one bounded observable or batch, chooses a fixed workflow/profile, queries only predeclared provider destinations, normalizes provider-native evidence, preserves provenance and failure semantics, and returns deterministic analytical/export projections.

**Intelligence Fabric v2** extends that registry with explicit secondary capabilities without changing baseline enrichment admission. Canonical `fast|standard|full` enrichment remains phase one and the only automatic fanout path. Graph pivots, search, owned-asset monitoring, malware/sample analysis, and defensive knowledge execute only through explicit normalized operations with exact type/mode matching, central authorization, fixed egress, bounded response/relationship limits, and retention/distribution policy.

PARA11AX exposes shared domain logic through three principal planes:

1. **Web / terminal UI** — browser analyst experience and browser-local workspace persistence.
2. **CLI / registered command fabric** — local operator and deterministic report/mission tooling.
3. **Remote MCP control plane** — OAuth/bearer-authenticated stateless `POST /mcp`, delegating to existing handlers and registered server-safe commands.

Specialist analyst utilities remain distinct authority layers: User Scanner, native Shodan operations, GreyNoise Project Swarm, Mission Workspace, Domain Investigation, and Investigation Workspace. They do not automatically become Evidence v2, Intelligence Kernel input, reputation voting, STIX, or attribution merely because PARA11AX transports them.

#### Architecture at a glance

![PARA11AX request path](../assets/brand/para11ax-architecture.svg)

#### Baseline Evidence v2 request path

```text
Client / Maltego / Web / CLI / MCP
  -> auth and bounded request validation
  -> strict canonical Evidence v2 classifier
  -> fixed workflow + fast|standard|full profile admission
  -> configured-provider filter
  -> Provider Value Scheduler v1.0
  -> central safeFetch fixed-egress boundary
  -> provider parser
  -> bounded cache
  -> Evidence Schema v2 normalization + provenance/integrity
  -> typed correlation / freshness / quality / huntability
  -> Intelligence Kernel v1.0 (IP reference policy)
  -> deterministic Decision Support
  -> Evidence Graph v1.0 + Guidance v1.0
  -> JSON / batch / deterministic report / STIX 2.1
```

`safeFetch` remains the hard egress boundary. Callers cannot choose arbitrary provider destinations, protocols, methods, credentials, redirects, parsers, or proxy routes. Scheduler ordering and the Intelligence Kernel add no provider egress.

#### Intelligence Fabric v2 explicit capability path

```text
REST / CLI / MCP explicit intelligence request
  -> authenticated request
  -> extended canonical subject classifier
  -> normalized operation -> fixed execution mode
  -> exact subject type + mode registry selection
  -> provider active/configuration state
  -> trusted central authorization
  -> deterministic value ranking
  -> at most four direct providers
  -> same fixed-egress provider runner
  -> provider parser + policy-bearing Evidence v2 normalization
  -> selected / executed / denied / unavailable / failures
  -> bounded intelligence envelope
```

The validated provider modes are:

```text
enrich | graph | search | monitor | analysis | knowledge
```

Only a capability with `mode: enrich`, `sensitivity: public`, and `authorization: none` may be `fanoutEligible: true`. Privileged or secondary capabilities cannot opt themselves into automatic fanout.

Authorization classes are:

```text
none | tenant | verified_domain | owned_network | explicit_case | explicit_action
```

Retention classes are:

```text
normal | restricted | ephemeral | no_store
```

`no_store` capabilities bypass shared Intelligence Fabric cache reads and writes. Distribution policy travels with normalized evidence and is enforced at export boundaries.

The public normalized operations are `pivot`, `search`, `identity`, `asset`, `supply-chain`, `malware`, and `knowledge`. The public request schema exposes only operation, indicator, optional asserted type, and optional baseline profile. It does not expose raw provider selection, provider URLs, trust flags, case identifiers, owned-CIDR claims, verified-domain lists, tenant claims, raw execution mode, or arbitrary upstream paths.

`pivot` deliberately composes two phases: baseline enrichment first, then graph expansion from explicit normalized relationships. This preserves the established Evidence v2 result while making secondary context and provenance separately visible.

#### Observable boundaries

Canonical automatic Evidence v2 workflows remain exactly:

```text
ip | domain | url | hash | cve | attack | asn | cidr | certificate
```

Certificate classification is explicit: `cert-sha256:<64-hex>`.

The Intelligence Fabric classifier additionally recognizes explicit capability subjects:

```text
pkg:<purl>                       -> package
ja3:<32-hex>                     -> TLS fingerprint
jarm:<62-hex>                    -> TLS fingerprint
ja4:<canonical-ja4>              -> TLS fingerprint
btc:<address> / eth:<address>    -> crypto address
<local>@<domain>                 -> email
user:<handle>                    -> username
hmsl-sha256:<64-hex>             -> privacy-preserving secret fingerprint
entity:<20-alnum>                -> legal entity id
```

These do not become new baseline workflows merely because the classifier can represent them. Capability policy still decides whether a matching registered mode exists and may execute.

Username `search` delegates to the isolated User Scanner path and is returned as internal/no-store scanner context; it is not manufactured into automatic Evidence v2 evidence.

#### Central authorization

Authorization context is server-trusted, not caller-trusted. Public REST/MCP bodies cannot inject ownership, verification, case, tenant, or trust fields.

Deployment-owned scopes are configured through server environment such as:

```text
PARA11AX_OWNED_CIDRS
PARA11AX_VERIFIED_DOMAINS
```

Owned-network policy is subject-aware: an IP must fall within an approved CIDR; a CIDR must be contained by an approved CIDR; and a domain must match an approved domain/subdomain rule. Authorization fails closed for unsupported or out-of-scope subjects.

Shadowserver is the reference owned-asset lane: `mode: monitor`, `sensitivity: owned_asset`, `authorization: owned_network`, `retentionClass: restricted`, `distribution: internal_only`. Its adapter is never a public open-world search provider.

GitGuardian HMSL is the reference secret-context lane: it accepts only `hmsl-sha256:` fingerprints, rejects raw-secret-shaped input before egress, requires explicit case authorization, uses `no_store`, and is `internal_only`.

#### Provider fabric and status

The current executable registry contains **54 active capabilities across 50 upstream services**. The established canonical enrichment fabric remains **39 upstream APIs/feeds**; sibling and intelligence-only capabilities do not silently change that baseline count or workflow membership.

Runtime status is deliberately precise:

- **implemented** — adapter/code exists and repository verification can exercise it;
- **configured / configured_unverified** — required server configuration is present, not proof of live success;
- **selected** — type/mode/configuration/authorization admitted the capability;
- **executed** — PARA11AX attempted it;
- **denied** — central authorization rejected it before egress;
- **unavailable** — missing/inactive/unconfigured for the operation;
- **production-verified** — an authorized live operation succeeded against the exact deployed SHA.

An upstream timeout, 429, 5xx, auth/entitlement rejection, parser error, or malformed successful schema remains a failure. `no_result` / `not_found` / `not_listed` remain source-scoped absence and never mean safe.

#### Provider Value Scheduler v1.0

Baseline provider admission remains owned by fixed workflow/profile rules. Scheduler v1.0 only decides deterministic attempt order among already-admitted providers.

Its static comparator uses authority, semantic uniqueness, direct threat value, pivot value, latency class, cost class, tier, then workflow order as fallback. It does not learn from evidence or omit sources after another provider returns a result.

Current IP reference invariants:

- **24-provider IP workflow** with unchanged membership;
- **48-call ceiling**: 24 providers × maximum two attempts;
- max concurrency 4;
- request deadline 20 seconds;
- every admitted provider remains scheduled;
- malformed scheduler metadata falls back deterministically;
- scheduler metadata is execution metadata, not a threat score.

Exact IP v1 order:

```text
rdap
-> tor-exit
-> ripestat
-> ipinfo
-> cloudflare-radar
-> feodo-tracker
-> threatfox
-> spamhaus-drop
-> abuseipdb
-> webamon
-> greynoise
-> urlscan
-> shodan
-> censys
-> modat
-> virustotal
-> threatminer
-> pulsedive
-> otx
-> misp-circl-osint
-> tweetfeed
-> dshield
-> misp-botvrij-osint
-> ransomlook
```

#### Intelligence Kernel v1.0

The Kernel is a pure deterministic derived-analysis layer between normalized Evidence v2/correlation and downstream analyst projections. The current reference implementation is IP-specific.

It can derive evidence strength, source diversity, corroboration independence, contradiction severity, temporal relevance, explicit relationship value, bounded one-hop pivots, threat context, hunt relevance, coverage impact, analyst priority, limitations, and deterministic trace rule IDs.

Kernel output is **derived context, not Evidence v2**. It performs no fetch, secret read, persistence, provider selection, evidence mutation, free-text entity invention, runtime learning, or LLM inference. A Kernel failure cannot invalidate otherwise usable Evidence v2.

Do not confuse the **Intelligence Kernel** with the **Intelligence Fabric**: the Kernel reasons deterministically over an enrichment result; the Fabric governs explicit secondary source execution.

#### Downstream projection boundaries

- **Evidence v2** — authoritative normalized provider observations, relationships, provenance, policy, and failures.
- **Correlation** — typed compatibility/freshness/quality layer.
- **Intelligence Kernel v1.0** — deterministic derived context.
- **Decision Support / Guidance** — deterministic projections over compatible evidence/context.
- **Evidence Graph v1.0** — explicit Evidence v2 facts/relationships only.
- **Operator context** — Shodan/User Scanner/Swarm and authorized imports; not automatic provider evidence.
- **MCP result** — transport representation of an existing capability, never a new authority class.
- **STIX 2.1** — evidence-derived export; restricted distribution remains enforced.

STIX export excludes references from evidence with `distribution: internal_only`. It also suppresses actor/malware relationship objects when the relationship's explicit provider provenance maps to internal-only evidence, closing the relationship side channel as well as the reference side channel. Provider-less legacy relationships retain their established compatibility behavior.

#### Remote MCP control plane

```text
MCP client
  -> POST /mcp
  -> public server/discover | initialize | tools/list
  -> OAuth 2.1 authorization-code + PKCE when required
  -> scoped OAuth access token or gateway bearer
  -> protocol/header validation | tools/call
  -> grouped PARA11AX MCP tool
  -> existing handler / pure domain function / registered safe command
  -> existing validation + fixed egress + semantic boundary
  -> structured MCP result
```

The current stateless protocol profile is `2026-07-28`. `Mcp-Method` must agree with the JSON-RPC method; `Mcp-Name` must agree with `params.name` for tool calls.

The current 15-tool catalog is:

```text
para11ax_capabilities
para11ax_enrich
para11ax_intelligence
para11ax_batch
para11ax_provider
para11ax_shodan
para11ax_swarm
para11ax_user_scan
para11ax_stix
para11ax_mission
para11ax_investigation
para11ax_case
para11ax_report
para11ax_command
para11ax_domain_investigation
```

`para11ax_command` resolves only exact registered command IDs and applies an additional remote policy gate. Browser-session-only, filesystem, local-admin, arbitrary shell, arbitrary URL fetch, secret-reading, and hidden persistent-session behavior are not exposed.

#### User Scanner request path

```text
Web / REST / MCP authorized request
  -> bounded email/username schema
  -> server-configured PARA11AX_USER_SCANNER_URL only
  -> optional PARA11AX_USER_SCANNER_TOKEN
  -> isolated Python worker
  -> bounded normalization
  -> operator/scanner result
  -> Evidence v2 unchanged unless an independent evidence workflow observes the same fact
```

The caller cannot choose worker host, proxy, concurrency, timeout, arbitrary module path, or bulk file.

#### Shodan analyst request path

```text
Web / MCP analyst
  -> gateway auth
  -> fixed command schema
  -> existing Shodan handler
  -> server-side SHODAN_API_KEY
  -> exact https://api.shodan.io origin
  -> bounded response normalization
  -> explicit operator output / credit impact
```

Approved commands are `host`, `search`, `count`, `stats`, `domain`, and `info`. Search is first-page only; raw banners are bounded/removed; download and scan submission are not exposed.

#### GreyNoise Project Swarm path

```text
Web / MCP analyst
  -> gateway auth
  -> fixed Swarm command schema
  -> server-side GREYNOISE_API_KEY
  -> exact https://api.greynoise.io origin
  -> bounded search/detail/pivot/diff or explicit single-session export
  -> operator context / explicit export
```

Approved operations are `search`, `get`, `unique`, `timeseries`, `diff`, and `export`. JSON and single-session exports are capped; bulk export, arbitrary destinations/methods/fields, and demo export are not exposed. Entitlement is an upstream state and is not inferred from key presence.

#### Mission, Domain Investigation, and Investigation Workspace

Mission Workspace is a deterministic client-relevance/hunt/KQL/result/ServiceNow-projection workflow. It never executes KQL or submits a ticket automatically.

Domain Investigation composes passive Evidence v2 with bounded authorized operator-context imports and deterministic report/STIX/handoff projections. Hosted active scanning is outside its contract.

Investigation Workspace v2 is a deterministic lifecycle over scope, observables, captured Evidence v2, explicit operator context, mission/hunt state, KQL validation, result import, analyst disposition, report, and ServiceNow-ready projection. Authority remains layered; stale dependencies block current report/ticket projections rather than being silently reused.

Browser state is local. MCP carries state explicitly between stateless calls; no cross-user workflow session is hidden on the server.

#### Trust boundaries

##### Caller -> gateway / MCP

Authentication and request/media/input validation happen before external execution. Public metadata discovery executes no analyst capability. Caller input never selects provider hosts, secret values, scheduler rank, fixed-egress exceptions, or trusted authorization scope.

##### Gateway -> provider

`safeFetch` enforces declared hosts, protocols, methods, redirect refusal, timeouts, and response ceilings. Provider credentials remain server-side. Secondary Intelligence Fabric execution adds exact type/mode selection, central authorization, retention, distribution, and direct-provider caps before the same provider runner.

##### Evidence -> derived context

The Intelligence Kernel, Decision Support, Guidance, reporting, graph, and STIX surfaces consume existing normalized facts under explicit projection rules. They do not gain authority merely by transforming data.

##### Operator utilities -> investigation

User Scanner, Shodan, and Swarm results are untrusted operator context. Explicit capture preserves that label. Service exposure, username matches, session records, pivots, and packet exports are not automatic compromise or attribution proof.

#### Scheduling and resilience

- baseline Evidence v2 provider concurrency: max 4;
- baseline request deadline: 20 seconds;
- retry: maximum two attempts/provider under the current policy;
- IP baseline: 24 providers / 48-call ceiling;
- batch: max 20 inputs, max 3 active indicators, max 200 baseline provider calls;
- Intelligence Fabric direct execution: max 4 selected providers;
- bounded pagination/relationship limits per secondary adapter;
- `no_store` skips shared cache;
- provider failures never become cached negative evidence;
- STIX: max 100 objects;
- MCP: stateless request handling, bounded body, tool-specific limits;
- Shodan/Swarm/User Scanner retain independent bounded paths.

#### Analytical model

There is deliberately no universal maliciousness score. Observed, inferred, contextual, operator, and analyst-judgment layers remain distinct. Absence is not benignness; infrastructure proximity is not attribution; KEV, EPSS, and CVSS remain different axes; defensive knowledge is not threat evidence; package dependencies are not compromise; crypto-abuse reports do not prove ownership; secret-fingerprint exposure does not justify raw-secret handling.

No LLM, adaptive source scheduler, or evidence-dependent provider suppression participates in the deterministic provider/evidence path.

#### State labels

- **Implemented:** present in source and repository verification.
- **Configured:** required runtime config exists; not a live-health claim.
- **Production-verified:** exact deployed SHA passed the specific authorized live check.
- **MCP transport-verified:** exact deployed source exposes required protocol/header behavior.
- **MCP client-connected:** a specific external MCP client is configured/authenticated and a call succeeded.
- **Gap/omitted:** intentionally absent because source, semantics, authorization, or boundedness did not meet the gate.

A READY deployment does not prove every provider credential, entitlement, owned-network scope, User Scanner worker, or external MCP client is configured.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
