<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### API

All responses are JSON unless a documented human-facing or binary export representation is explicitly negotiated. Production clients should use HTTPS. Protected REST requests use `Authorization: Bearer <PARA11AX_TOKEN>`.

PARA11AX has two remote protocol surfaces over the same bounded domain logic:

- REST under `/api/para11ax/*`;
- OAuth-linked stateless MCP tool execution at `POST /mcp`, with public protocol/tool discovery.

MCP does not duplicate provider, Intelligence Fabric, scanner, mission, Domain Investigation, Investigation Workspace, case, or report implementations. It delegates to existing handlers and preserves their validation, fixed-host egress, evidence semantics, authorization, retention, and side-effect boundaries. See [`MCP.md`](MCP.md).

#### Canonical Evidence v2 workflows

Baseline Evidence v2 indicator types are `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, and `certificate`. Certificate input is explicit: `cert-sha256:<64-hex>`. Fixed profiles are `fast`, `standard`, and `full`; callers cannot select arbitrary baseline providers.

Profile admission and execution priority remain separate. Admitted baseline providers are ordered by **Provider Value Scheduler v1.0**. The current IP workflow retains 24 admitted providers, a 48-call ceiling, maximum concurrency 4, and the 20-second request deadline. Returned evidence never changes which already-admitted baseline source is allowed to run.

#### Intelligence Fabric explicit operations

`POST /api/para11ax/intelligence` is the normalized secondary-capability surface. It accepts only:

```json
{
  "operation": "pivot",
  "indicator": "8.8.8.8",
  "type": "ip",
  "profile": "standard"
}
```

`type` and `profile` are optional. The only operation names are:

```text
pivot
search
identity
asset
supply-chain
malware
knowledge
```

The public schema intentionally exposes no provider name, provider URL, raw upstream query path, mode override, trust flag, case ID, verified-domain list, owned-CIDR list, tenant claim, credential, or fetch option.

The extended classifier can route explicit capability subjects including package PURLs (`pkg:`), TLS fingerprints (`ja3:`, `jarm:`, `ja4:`), crypto addresses (`btc:`, `eth:`), email, `user:` usernames, `hmsl-sha256:` privacy-preserving secret fingerprints, and `entity:` legal-entity IDs. These are not new automatic baseline enrichment workflows.

Secondary execution is exact type + registered mode, configuration-aware, centrally authorized, deterministically ranked, and capped at four direct providers. `no_store` capabilities bypass shared cache reads/writes. `no_result` remains source-scoped absence, never a safety verdict.

`pivot` is the one operation that first obtains compatible baseline enrichment and then expands only explicit normalized relationships through graph-mode providers. This preserves the baseline enrichment envelope while making phase-two provenance visible. Username `search` delegates to the bounded User Scanner path and is returned as internal/no-store scanner context rather than automatic Evidence v2.

Owned-asset `asset` requests fail closed unless the canonical subject is inside trusted server-owned scope. Callers cannot inject ownership scope. `knowledge`, `supply-chain`, and `malware` likewise execute only providers whose declared subject type and mode match the request.

#### Route inventory

- `POST /mcp` — public MCP discovery plus OAuth/bearer-protected stateless tool execution; current profile `2026-07-28`; **15 grouped tools**.
- `GET /.well-known/oauth-protected-resource` and `/mcp` suffix variant — OAuth resource metadata.
- `GET /.well-known/oauth-authorization-server` — OAuth authorization-server metadata.
- `GET|POST /oauth/authorize` — fixed ChatGPT CIMD consent flow.
- `POST /oauth/token` — public-client authorization-code exchange with `S256` PKCE.
- `GET /api/para11ax/meta` — public static capabilities and hard limits.
- `GET /api/para11ax/health` — bearer-protected readiness; `Cache-Control: no-store`.
- `GET /api/para11ax/status` — bearer-protected count-only runtime state; `Cache-Control: no-store`.
- `POST /api/para11ax/enrich` — one canonical baseline indicator.
- `POST /api/para11ax/intelligence` — one normalized explicit Intelligence Fabric operation.
- `POST /api/para11ax/batch` — 1–20 baseline indicators; max 3 active indicators / 200 provider calls.
- `POST /api/para11ax/stix` — enrich then export bounded STIX 2.1.
- `POST /api/para11ax/user-scanner` — isolated bounded email/username active OSINT.
- `POST /api/para11ax/shodan` — bounded authenticated native Shodan operator commands.
- `POST /api/para11ax/swarm` — bounded authenticated GreyNoise Project Swarm search/detail/pivots/diff/explicit export.
- `POST /api/para11ax/provider` — one authenticated registered **baseline-compatible** provider against one canonical Evidence v2 indicator.
- `POST /api/para11ax/self-test` — signed production self-test path used by deployment verification.

Unknown `/api/para11ax/*` paths fail closed. `/mcp` is routed explicitly before the REST catch-all.

#### `POST /mcp`

ChatGPT uses authorization-code + `S256` PKCE to obtain a time-bounded `para11ax:use` access token bound to `https://para11ax.vercel.app/mcp`. Existing trusted clients can continue using the same gateway bearer as protected REST routes.

Modern request headers:

```text
Authorization: Bearer <token>
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
Mcp-Method: <json-rpc method>
Mcp-Name: <tool name>   # tools/call only
```

Public discovery methods are `server/discover`, `initialize`, `notifications/initialized`, `ping`, and `tools/list`. They execute no analyst capability. For modern requests, `Mcp-Method` must equal the JSON-RPC body method and `Mcp-Name` must equal `params.name` on `tools/call`.

Current grouped tools:

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

Representative intelligence call:

```json
{
  "jsonrpc":"2.0",
  "id":2,
  "method":"tools/call",
  "params":{
    "name":"para11ax_intelligence",
    "arguments":{"operation":"knowledge","indicator":"T1059"}
  }
}
```

Stateful logical workflows remain transport-stateless. Mission, Domain Investigation, Investigation Workspace, and case tools return explicit state which the client supplies on subsequent calls. `para11ax_command` is a registered-command fallback, not arbitrary shell execution.

#### `POST /api/para11ax/enrich`

```json
{"indicator":"203.0.113.10","profile":"standard"}
```

Normalized `ok`/`partial` results retain authoritative Evidence v2 and deterministic analytical projections. The IP reference path can include top-level `intelligence` from **Intelligence Kernel v1.0**, followed by kernel-aware decision/guidance. Evidence Graph v1.0 remains an explicit-evidence projection and does not promote Kernel-derived relationships into provider evidence.

The Intelligence Kernel is distinct from the Intelligence Fabric API. Kernel output is deterministic derived context over one baseline enrichment; `/intelligence` is the explicit capability-execution surface.

#### `POST /api/para11ax/batch`

```json
{"indicators":["192.0.2.44","evil.example"],"profile":"standard"}
```

Limits: 1..20 strings, max 3 active indicators, max 200 baseline provider calls globally, one shared deadline, canonical de-duplication, and no provider override.

#### `POST /api/para11ax/stix`

Uses the same single-indicator contract as `/enrich`. The gateway enriches first and maps the bounded result to STIX 2.1; caller-supplied enrichment objects are rejected.

STIX export remains evidence-derived. `internal_only` evidence references are excluded. Actor/malware relationship objects are also suppressed when their explicit provider provenance maps to `internal_only` evidence, preventing restricted source context from leaking through relationship projection. Kernel conclusions do not become new STIX evidence or attribution facts.

#### `POST /api/para11ax/user-scanner`

Separate active-OSINT capability used by the `user-scanner` command and by MCP `para11ax_user_scan`.

```json
{"scanType":"username","target":"example_handle","crossScan":false,"noNsfw":true}
```

The caller cannot select the worker URL, proxy, concurrency, arbitrary destination, or timeout. Output remains separate from baseline Evidence v2 and Intelligence Kernel reasoning. Scanner hits are leads until corroborated.

#### `POST /api/para11ax/shodan`

Bearer required. Approved commands are exactly:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

The server reads `SHODAN_API_KEY` and contacts only `https://api.shodan.io`. Caller-selected URLs/pages/methods/credentials and `shodan download` are disabled. Search is first-page only; large raw banners are removed. Credit impact remains explicit.

#### `POST /api/para11ax/swarm`

Bearer required. Approved operations are `search`, `get`, `unique`, `timeseries`, `diff`, and explicit single-session `export`. The server reads `GREYNOISE_API_KEY` and contacts only `https://api.greynoise.io`.

Time ranges, query lengths, pagination inputs, pivot fields, workspace aliases, and result sizes are bounded. JSON and individual binary exports are capped at 4 MiB. Bulk session export, arbitrary workspace UUIDs, caller-selected destinations/methods/headers/credentials, and demo export are not exposed. Account entitlement is not inferred from key presence.

Successful read results are operator context and can be explicitly captured by Investigation Workspace without becoming automatic Evidence v2.

#### `POST /api/para11ax/provider`

Bearer required. This route executes exactly one registered provider through the established **canonical Evidence v2 provider gateway** against a canonical baseline indicator:

```json
{"provider":"rdap","indicator":"203.0.113.10","type":"ip"}
```

The body accepts only `provider`, `indicator`, and optional asserted `type`. Caller input cannot set URL, method, credential, timeout, parser, response ceiling, headers, raw body, or fetch implementation. Intelligence-only subjects and secondary capability semantics belong on `/api/para11ax/intelligence`, not this legacy direct-provider route.

#### Provider and authorization status semantics

Remote status should be read precisely:

- **implemented** — adapter/code exists;
- **configured / configured_unverified** — required server configuration is present, not proof of live health;
- **selected** — type/mode/configuration/authorization policy admitted the capability for an intelligence operation;
- **executed** — PARA11AX attempted that provider;
- **denied** — central authorization rejected it before execution;
- **unavailable** — inactive, missing, or unconfigured;
- **production-verified** — an authorized live request succeeded against the exact deployed SHA.

Server-owned authorization configuration such as `PARA11AX_OWNED_CIDRS` and `PARA11AX_VERIFIED_DOMAINS` is never accepted from the public request body.

#### Common errors

- `400` — invalid request/indicator/profile/batch/intelligence operation, type mismatch, unsupported field, or invalid MCP routing agreement.
- `401 unauthorized`.
- `404 provider_not_found` for an unknown direct-provider name.
- `409 provider_inactive` or `provider_unconfigured` for a direct provider that cannot be admitted.
- `405 method_not_allowed`; `GET /mcp` intentionally returns 405 with `Allow: POST`.
- `413 payload_too_large`.
- `415 unsupported_media_type`.
- User Scanner uses controlled worker errors.
- Provider rate limits, auth/entitlement errors, timeouts, malformed schemas, and transport failures remain explicit operational failures and are never converted into threat evidence.

#### Security invariants

Caller input never selects arbitrary provider hosts, Shodan/GreyNoise/worker hosts, methods, secrets, trusted ownership scope, or raw provider-routing fields. Baseline provider egress remains fixed through `safeFetch`. Intelligence Fabric secondary capabilities use the same fixed-egress contract plus exact mode/type admission, central authorization, retention/distribution policy, and bounded direct execution. Provider Value Scheduler v1.0 and Intelligence Kernel v1.0 add no arbitrary egress or LLM path. MCP exposes no host shell, arbitrary fetch/filesystem, local-admin operation, or hidden server-side workflow state.

See [`MCP.md`](MCP.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`PROVIDERS.md`](PROVIDERS.md), [`THREAT-MODEL.md`](THREAT-MODEL.md), and [`SECURITY-CONTROLS.md`](SECURITY-CONTROLS.md).

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
