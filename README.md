<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
<p align="center">
  <img src="assets/brand/para11ax-readme-hero-v9.svg" alt="PARA11AX — provenance-first CTI enrichment and analyst operations" width="100%">
</p>

<p align="center">
  <a href="https://github.com/ger1e/para11ax/actions/workflows/tooling-smoke.yml"><img src="https://github.com/ger1e/para11ax/actions/workflows/tooling-smoke.yml/badge.svg" alt="Tooling smoke"></a>
  <a href="https://github.com/ger1e/para11ax/actions/workflows/codeql.yml"><img src="https://github.com/ger1e/para11ax/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
</p>

<p align="center"><sub>
  <a href="https://para11ax.vercel.app/app/"><strong>ENTER ANALYST UI</strong></a> ·
  <a href="https://para11ax.vercel.app/">LANDING</a> ·
  <a href="docs/MCP.md"><strong>MCP</strong></a> ·
  <a href="docs/API.md">API</a> ·
  <a href="docs/ARCHITECTURE.md">ARCHITECTURE</a> ·
  <a href="docs/PROVIDERS.md">PROVIDERS</a> ·
  <a href="docs/SHELL.md">SHELL</a> ·
  <a href="docs/IDENTITY-OSINT.md">IDENTITY OSINT</a> ·
  <a href="docs/GOOGLE-DORKING.md">DORKING</a> ·
  <a href="docs/ANALYST-MISSION-PACK.md">MISSION</a> ·
  <a href="docs/DOMAIN-INVESTIGATION.md">DOMAIN INVESTIGATION</a> ·
  <a href="docs/SHODAN-SHELL.md">SHODAN SHELL</a> ·
  <a href="docs/GREYNOISE-SWARM.md">GREYNOISE SWARM</a> ·
  <a href="SECURITY.md">SECURITY</a>
</sub></p>

> [!IMPORTANT]
> Personal research / lab surface. Do not send commercial-client, internal-enterprise, restricted, secret, or otherwise sensitive data without explicit authorization and suitable handling. User Scanner is active OSINT; Shodan commands can consume account credits; GreyNoise Swarm can expose session metadata and explicit packet/raw exports; owned-asset and secret-context Intelligence Fabric capabilities have additional authorization/retention controls. Use these surfaces only for authorized defensive research.

<sub><strong>01 // SYSTEM PROFILE</strong></sub>

PARA11AX is a bounded, provenance-first CTI enrichment/correlation core with deterministic analysis and isolated analyst operations. Canonical observables enter fixed **Evidence v2** workflows. Profile admission remains separate from execution priority: **Provider Value Scheduler v1.0** orders already-admitted baseline providers without evidence-dependent suppression. The IP reference path then projects **Intelligence Kernel v1.0** derived context over normalized evidence and correlation.

**Intelligence Fabric v2** extends the same fixed-egress provider registry with explicit secondary capabilities for graph pivots, search, owned-asset monitoring, malware/context analysis, defensive knowledge, package supply-chain context, TLS/malware context, crypto-abuse context, historical web context, and privacy-preserving secret-exposure checks. These capabilities never widen `fast|standard|full` baseline enrichment automatically. Exact type/mode admission, central authorization, response/relationship bounds, retention, and distribution policy remain mandatory.

**MCP control plane** exposes the functional analyst surface through `POST https://para11ax.vercel.app/mcp`. ChatGPT links with OAuth 2.1 authorization-code + PKCE; trusted clients can retain the direct gateway bearer. The current stateless MCP catalog contains **15 grouped tools**, including dedicated normalized `para11ax_intelligence` and `para11ax_domain_investigation` surfaces. Browser cosmetics, arbitrary shell/fetch/filesystem access, and local-admin operations remain outside MCP.

**Mission Workspace v1** and **Investigation Workspace v2** provide deterministic client-relevance, hunt, KQL-validation, result-analysis, reporting, and ServiceNow-ready projections. KQL is never executed automatically and ServiceNow output is never submitted automatically. Browser state stays local; MCP state is explicit state-in/state-out.

The Intelligence Kernel does not fetch, mutate, or manufacture evidence. Raw **Evidence v2 remains authoritative**. Kernel output is derived context. The Intelligence Fabric is different: it governs explicit secondary provider execution under policy.

<sub><strong>STATE</strong> — OPERATIONAL CORE<br/>
<strong>BASELINE INPUTS</strong> — `ip` · `domain` · `url` · `hash` · `cve` · `attack` · `asn` · `cidr` · `certificate` (`cert-sha256:&lt;64-hex&gt;`)<br/>
<strong>EXTENDED SUBJECTS</strong> — `pkg:` PURL · `ja3:` / `jarm:` / `ja4:` · `btc:` / `eth:` · email · `user:` · `hmsl-sha256:` · `entity:`; capability-routed, not new baseline workflows<br/>
<strong>MCP</strong> — `/mcp` · stateless `2026-07-28` profile · 15 grouped tools · OAuth 2.1/PKCE or gateway bearer<br/>
<strong>INTELLIGENCE FABRIC</strong> — `enrich | graph | search | monitor | analysis | knowledge` · max 4 direct providers · privileged/secondary capabilities never fan out automatically · `no_store` bypasses shared cache<br/>
<strong>SCHEDULER</strong> — Provider Value Scheduler v1.0 · deterministic static ordering · profile admission remains separate<br/>
<strong>IP REFERENCE</strong> — 24-provider baseline IP workflow · 48-call ceiling · max 4 active · max 2 attempts/provider · 20 s deadline<br/>
<strong>INTELLIGENCE KERNEL</strong> — IP reference policy · deterministic derived context · no LLM · no synthetic universal threat score<br/>
<strong>IDENTITY OSINT</strong> — defensive exact-identifier discovery + isolated User Scanner; operator context, not identity proof<br/>
<strong>SHODAN OPS</strong> — `shodan host|search|count|stats|domain|info` · fixed upstream · server-side key · explicit credit impact<br/>
<strong>GREYNOISE SWARM</strong> — `swarm search|get|unique|timeseries|diff|export` · fixed upstream · bounded session/pivot/export surface<br/>
<strong>MISSION</strong> — deterministic workspace · relevance · hunt · KQL validation · result analysis · ServiceNow projection<br/>
<strong>DOMAIN INVESTIGATION</strong> — passive Evidence v2 · bounded operator-context imports · report/STIX/handoff · no hosted active scanning<br/>
<strong>OUTPUT</strong> — Evidence v2 · Intelligence Fabric envelopes · Intelligence Kernel context · Decision Support · Evidence Graph v1.0 · Guidance v1.0 · JSON · batch · STIX 2.1 · deterministic reports<br/>
<strong>IDENTITY</strong> — repository/package/CLI `para11ax` · bearer `PARA11AX_TOKEN` · REST `/api/para11ax/*` · MCP `/mcp`</sub>

<sub><strong>02 // REQUEST PATHS</strong></sub>

<p align="center"><img src="assets/brand/para11ax-readme-architecture-v6.svg" alt="PARA11AX bounded request path through deterministic provider scheduling, fixed egress, Evidence v2 and Intelligence Kernel v1.0" width="100%"></p>

Canonical baseline flow:

```text
caller
  -> auth
  -> canonical Evidence v2 classifier
  -> fixed profile admission
  -> Provider Value Scheduler v1.0
  -> safeFetch / fixed egress
  -> provider parser
  -> bounded cache
  -> Evidence v2
  -> typed correlation
  -> Intelligence Kernel v1.0
  -> Decision Support / Evidence Graph / Guidance
  -> report / STIX
```

Explicit Intelligence Fabric flow:

```text
caller
  -> auth
  -> extended canonical subject classifier
  -> normalized operation -> fixed mode
  -> exact type + mode registry selection
  -> configuration + central authorization
  -> deterministic ranking (max 4)
  -> same fixed-egress provider runner
  -> policy-bearing normalized evidence / operator result
  -> selected / executed / denied / unavailable / failures
```

`safeFetch` remains the hard egress boundary. Caller input never chooses arbitrary provider hosts, methods, credentials, redirects, or raw provider routing. Secondary capabilities do not participate in baseline fanout merely because they are registered.

The current baseline IP workflow retains its **24-provider membership** and **48-call ceiling**. Evidence never changes which already-admitted baseline source is allowed to run.

MCP remains a remote control plane over existing capabilities, not another evidence source:

```text
MCP client
  -> POST /mcp
  -> public discovery
  -> OAuth/bearer auth
  -> MCP header/body agreement
  -> existing PARA11AX handler / safe registered command
  -> same validators / fixed destinations / semantic boundaries
  -> structured result
```

<details>
<summary><strong>Remote/API surface</strong></summary>

- `POST /mcp` — public metadata discovery plus authenticated stateless tool execution.
- `GET /.well-known/oauth-protected-resource*` / `GET /.well-known/oauth-authorization-server` — OAuth discovery.
- `GET|POST /oauth/authorize` / `POST /oauth/token` — ChatGPT authorization-code + PKCE flow.
- `GET /api/para11ax/meta` — public static capability/hard-limit metadata.
- `GET /api/para11ax/health` — bearer-protected readiness.
- `GET /api/para11ax/status` — bearer-protected aggregate runtime state.
- `POST /api/para11ax/enrich` — one baseline indicator, fixed workflow/profile.
- `POST /api/para11ax/intelligence` — one normalized explicit Intelligence Fabric operation.
- `POST /api/para11ax/batch` — bounded baseline batch.
- `POST /api/para11ax/stix` — enrich then bounded STIX 2.1 export.
- `POST /api/para11ax/user-scanner` — bounded email/username active OSINT.
- `POST /api/para11ax/shodan` — bounded native Shodan operator commands.
- `POST /api/para11ax/swarm` — bounded GreyNoise Swarm operations.
- `POST /api/para11ax/provider` — one registered baseline-compatible provider through the legacy direct-provider route.
- `POST /api/para11ax/self-test` — signed production-verification path.
- Unknown `/api/para11ax/*` — controlled fail-closed 404.

MCP Intelligence Fabric example:

```json
{"name":"para11ax_intelligence","arguments":{"operation":"knowledge","indicator":"T1059"}}
```

REST Intelligence Fabric example:

```json
{"operation":"supply-chain","indicator":"pkg:npm/react@18.2.0"}
```

Complete contracts: [`docs/MCP.md`](docs/MCP.md), [`docs/API.md`](docs/API.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

</details>

<sub><strong>03 // INTELLIGENCE FABRIC v2</strong></sub>

The executable registry currently contains **54 active provider capabilities spanning 50 upstream services**. The established canonical enrichment fabric remains **39 upstream APIs and feeds**. Sibling and intelligence-only capabilities are explicit and non-fanout by default.

Representative secondary capabilities include:

- VirusTotal graph, urlscan result graph, Censys search/history;
- VulnCheck exploit context and deps.dev package dependency context;
- abuse.ch SSLBL JA3 context, YARAify similarity, CERT Polska MWDB configuration context;
- Internet Archive Wayback CDX historical web context;
- MITRE D3FEND defensive-technique knowledge;
- Chainabuse crypto-address abuse reports;
- Team Cymru IP-to-ASN/network identity;
- Shadowserver owned-asset reports under server-owned scope;
- GitGuardian HMSL privacy-preserving secret-fingerprint checks.

Capability admission remains explicit. Public callers cannot supply trusted ownership/verification/case/tenant claims. Server-owned scopes such as `PARA11AX_OWNED_CIDRS` and `PARA11AX_VERIFIED_DOMAINS` are deployment configuration, not request fields.

A provider can be implemented, configured, selected, executed, denied, unavailable, or production-verified. Those states are intentionally different. A configured credential does not prove entitlement or upstream health. An upstream failure is not a negative finding; `no_result` is not safe.

Future automatic-workflow admission is measured by the offline **Provider Value Benchmark / Admission Gate**, which evaluates uniqueness, material graph yield, reliability, latency, and decision-changing value from recorded/local corpora. Benchmark output does not mutate routing automatically.

<sub><strong>04 // SEMANTIC FIREWALL</strong></sub>

<p align="center"><img src="assets/brand/para11ax-readme-semantics-v5.svg" alt="PARA11AX semantic firewall separating authoritative evidence from deterministic derived context and unsupported inference" width="100%"></p>

**OBSERVED ≠ INFERRED ≠ CONTEXTUAL.** The authority of an object does not increase because it passed through MCP, a report, a graph, or a prettier UI.

<sub><strong>DERIVED CONTEXT ≠ EVIDENCE</strong> — Intelligence Kernel output never becomes new Evidence v2<br/>
<strong>OPERATOR CONTEXT ≠ EVIDENCE</strong> — User Scanner, Shodan, GreyNoise Swarm, and authorized imports remain contextual unless an independent evidence workflow observes the same fact<br/>
<strong>CAPABILITY EXECUTION ≠ BASELINE FANOUT</strong> — graph/search/monitor/analysis/knowledge providers never silently join `fast|standard|full`<br/>
<strong>ABSENCE ≠ BENIGN</strong> — `no_result`, `not_listed`, `not_found`, and `no_association` remain source-scoped absence<br/>
<strong>FAILURE ≠ NEGATIVE EVIDENCE</strong> — timeout, 429, 5xx, auth/entitlement, parser, and schema failures remain failures<br/>
<strong>INFRASTRUCTURE ≠ ATTRIBUTION</strong> — hosting, ASN, DNS, certificates, network identity, exposure, or malware proximity do not manufacture actor attribution<br/>
<strong>IDENTITY HIT ≠ IDENTITY PROOF</strong> — username/email/platform matches do not prove same-person identity or compromise<br/>
<strong>CRYPTO REPORT ≠ OWNERSHIP PROOF</strong> — reported address abuse does not prove wallet ownership or actor identity<br/>
<strong>SECRET FINGERPRINT ≠ RAW SECRET</strong> — HMSL accepts a privacy-preserving fingerprint; raw-secret-shaped input is rejected before egress<br/>
<strong>KEV ≠ EPSS ≠ CVSS</strong> — observed exploitation, probability, and severity remain separate axes</sub>

**No universal maliciousness score. No universal identity score. No LLM inference layer in the deterministic evidence path.**

<sub><strong>05 // EXPORT & DISTRIBUTION</strong></sub>

Evidence carries distribution/retention policy through normalization. `no_store` capabilities bypass shared Intelligence Fabric cache. `internal_only` evidence is excluded from shareable STIX references, and actor/malware relationship objects are also suppressed when their explicit provider provenance maps to internal-only evidence. Restricted source context therefore cannot leak merely through a relationship edge.

Kernel-derived conclusions do not become new STIX evidence or attribution facts. Swarm packet/raw exports remain explicit export material only. Investigation operator context stays operator context.

<sub><strong>06 // SECURITY & VERIFICATION</strong></sub>

<sub><strong>AUTH</strong> — OAuth 2.1/PKCE or gateway bearer protects MCP execution; bearer protects private REST surfaces<br/>
<strong>EGRESS</strong> — exact declared provider hosts/methods/protocols; secondary capabilities use the same fixed-egress boundary<br/>
<strong>AUTHORIZATION</strong> — trusted scopes are server-owned; public callers cannot self-assert owned network/domain/case/tenant authority<br/>
<strong>SECRETS</strong> — provider/worker credentials remain server-side; MCP/REST never expose environment-secret values<br/>
<strong>RETENTION</strong> — `no_store` bypasses shared cache; internal-only distribution stays enforced at export boundaries<br/>
<strong>STATE</strong> — browser workspace remains local; MCP workflow state is explicit, not hidden server persistence<br/>
<strong>CI</strong> — protected `main` requires Tooling smoke; CodeQL runs alongside it<br/>
<strong>DEPLOY</strong> — repository/CI proof and production-deployment proof are separate states</sub>

Representative operator CLI:

```text
para11ax doctor
para11ax providers list
para11ax providers env-template
para11ax providers probe --all
para11ax release verify
para11ax report compile <snapshot.json> --out <dir>
```

<sub><strong>07 // DEEP DOCS</strong></sub>

<sub>[BRAND](docs/BRAND.md) · [MCP](docs/MCP.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [END-TO-END](docs/END-TO-END-EXAMPLE.md) · [EVIDENCE](docs/EVIDENCE-SCHEMA.md) · [PROVIDERS](docs/PROVIDERS.md) · [API](docs/API.md) · [SHELL](docs/SHELL.md) · [DOMAIN INVESTIGATION](docs/DOMAIN-INVESTIGATION.md) · [IDENTITY OSINT](docs/IDENTITY-OSINT.md) · [GOOGLE DORKING](docs/GOOGLE-DORKING.md) · [MISSION](docs/ANALYST-MISSION-PACK.md) · [SHODAN SHELL](docs/SHODAN-SHELL.md) · [GREYNOISE SWARM](docs/GREYNOISE-SWARM.md) · [THREAT MODEL](docs/THREAT-MODEL.md) · [SECURITY CONTROLS](docs/SECURITY-CONTROLS.md) · [OPERATIONS](docs/OPERATIONS.md) · [QA](docs/QA-REPORT.md) · [PUBLIC RELEASE](docs/PUBLIC-RELEASE-CHECKLIST.md) · [MANIFEST](release-manifest.json)</sub>

<p align="center"><img src="assets/brand/para11ax-readme-footer-v2.svg" alt="PARA11AX operating principles — Per Aspera Ad Astra" width="100%"></p>

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>

<p align="center"><img src="assets/brand/para11ax-radar-lockup.svg" alt="PARA11AX" width="180"></p>
