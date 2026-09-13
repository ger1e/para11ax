<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# MCP control plane

PARA11AX exposes its functional analyst surface through one authenticated remote Model Context Protocol endpoint:

```text
https://para11ax.vercel.app/mcp
```

MCP is a control plane over existing PARA11AX domain logic, not a second implementation. Enrichment, User Scanner, Shodan, GreyNoise Swarm, Mission Workspace, Domain Investigation, Investigation Workspace, cases, reports and registered commands delegate into the same bounded handlers used elsewhere.

The transport implements the stateless `2026-07-28` profile and retains bounded `2025-06-18` initialize compatibility. Repository, CI, deployment, OAuth transport, live credential capability and ChatGPT-connection proof are separate states.

## Authentication and transport

Protocol discovery is public so a client can initialize and inspect the 14 tool descriptors before linking. Public methods are limited to `server/discover`, `initialize`, `notifications/initialized`, `ping`, and `tools/list`; they execute no analyst capability.

Protected execution accepts either a PARA11AX OAuth access token or the existing gateway bearer for trusted non-OAuth clients.

```text
Authorization: Bearer <token>
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
```

OAuth discovery and linking use:

```text
GET  /.well-known/oauth-protected-resource
GET  /.well-known/oauth-protected-resource/mcp
GET  /.well-known/oauth-authorization-server
GET  /oauth/authorize
POST /oauth/authorize
POST /oauth/token
```

The current authorization server uses authorization-code + `S256` PKCE, the exact `https://para11ax.vercel.app/mcp` resource, `para11ax:use`, and optional `offline_access`. When `offline_access` is granted, refresh-token flow is supported so a correctly linked client can maintain connectivity without repeatedly handling the gateway credential.

Current OAuth tokens are **sealed**, not HMAC-signed JWT lookalikes. Token confidentiality/integrity uses AES-256-GCM with a random nonce, authenticated additional data and purpose-separated scrypt-derived key material. Access and refresh tokens have distinct purposes and bounded lifetimes. The gateway secret is never returned to the MCP client. Rotating the relevant server secret invalidates issued material.

Legacy pre-refresh sessions cannot be silently upgraded because the old authorization server did not issue refresh tokens. The obsolete HMAC token format is not re-enabled as a compatibility shortcut.

Core MCP tool-auth failures preserve the result-level `_meta["mcp/www_authenticate"]` challenge. At the canonical external `/mcp` edge, a valid authentication-required result is normalized to HTTP `401` with `WWW-Authenticate`, which is friendlier to external clients while preserving the internal MCP result model. Malformed, non-Bearer, control-character or oversized challenges are rejected rather than reflected.

Modern routing also validates `Mcp-Method`; `Mcp-Name` is required for `tools/call` and must match `params.name`. Mismatches fail closed.

The endpoint is stateless. Mission, Domain Investigation, investigation and analyst-case state is returned to the client and supplied on subsequent related calls. `/mcp` has no hidden cross-user workflow session.

## Discovery and schemas

Canonical sequence:

```text
server/discover
  -> tools/list
  -> tools/call
```

`tools/list` returns all 14 tools with schemas and annotations. The catalog is the authoritative remote capability inventory. Bounded operator tools advertise bounded schemas as well as enforcing runtime validation. In particular, `para11ax_swarm` and `para11ax_user_scan` use `additionalProperties: false`; supported enums, fields and numeric/string limits are explicit. This prevents the tool model from advertising a looser contract than the server actually accepts.

Schema metadata is not the security boundary by itself. Runtime validators remain authoritative and reject unsupported command/field combinations, oversize input and invalid ranges even if a client ignores JSON Schema.

## Functional surface

| Tool | Capability | Authority / side effect |
| --- | --- | --- |
| `para11ax_capabilities` | catalog, registered safe commands, health/status/meta | read-only |
| `para11ax_enrich` | Evidence v2 single-observable enrichment | bounded external lookup |
| `para11ax_batch` | bounded batch enrichment | bounded external lookup |
| `para11ax_provider` | one registered provider | bounded external lookup |
| `para11ax_shodan` | bounded Shodan operator operations | external lookup; some operations consume credits |
| `para11ax_swarm` | Swarm search/get/export/unique/timeseries/diff | read/pivot plus explicit export |
| `para11ax_user_scan` | isolated email/username OSINT scanner | active open-world OSINT |
| `para11ax_stix` | deterministic STIX object projection from enrichment | read-only projection |
| `para11ax_mission` | mission profile/context/relevance/hunt/KQL/result/ServiceNow workflow | explicit client-carried state |
| `para11ax_domain_investigation` | build/import/show/report/STIX/handoff for suspicious-domain investigation | explicit client-carried state; no scanner/provider execution |
| `para11ax_investigation` | Investigation Workspace create/status/mutate/report/import/export | explicit client-carried state |
| `para11ax_case` | portable analyst case operations | explicit client-carried state |
| `para11ax_report` | deterministic report render/quality/manifest | read-only projection |
| `para11ax_command` | exact registered server-safe command | policy-dependent registered operation |

This is functional parity, not UI mirroring. Browser theme/audio/focus/history controls and local administration are not remote analyst capabilities.

## Bounded operator schemas

### User Scanner

Required: `scanType`, `target`.

Optional bounded fields: `category`, `module`, `crossScan`, `noNsfw`. `scanType` is `email|username`; target is capped at 320 characters; category/module use a safe 64-character identifier grammar. Runtime validation also rejects category+module conflicts and invalid control characters.

```json
{
  "name": "para11ax_user_scan",
  "arguments": {
    "scanType": "username",
    "target": "example_handle"
  }
}
```

The result is an investigative lead. Upstream `rawFound` is not accepted as proof; normalized `found` counts only exact target matches while ambiguous matches remain `unverified`.

### GreyNoise Project Swarm

Commands: `search`, `get`, `export`, `unique`, `timeseries`, `diff`.

The schema advertises the bounded command fields for session ID, scope, time range, query, page/page size, export type, pivot field/counts, interval, size, diff workspaces/mode and pagination token. Runtime validation enforces command-specific combinations. Arbitrary fields do not pass through to GreyNoise.

Swarm is operator context, not another Evidence v2 provider. Workspace/demo capability depends on upstream entitlement. Individual JSON/binary responses remain bounded by the underlying Swarm handler.

### Domain Investigation

`para11ax_domain_investigation` exposes these exact actions:

`build` · `surface_import` · `vulnerability_import` · `show` · `report` · `stix` · `handoff`

`build` accepts a canonical domain Evidence v2 enrichment. Import actions accept a previously returned Domain Investigation artifact plus bounded scalar-only records. The server stores no hidden Domain Investigation state: build/import transitions return the full client-carried artifact, while `show`, report, STIX and handoff return bounded public projections.

The Domain Investigation body allowance is raised only on this exact authenticated grouped-tool path so a valid client-carried artifact or import can cross the ordinary 128 KiB MCP ceiling. Unauthenticated requests remain behind the public ceiling, and unrelated tools do not inherit the larger allowance.

Imported discovery/vulnerability records are `operator_context`, not Evidence v2. The tool never performs active scanning, provider execution or arbitrary egress. Full authority and recommendation semantics are documented in [`DOMAIN-INVESTIGATION.md`](DOMAIN-INVESTIGATION.md).

## State round trips

Mission example:

```text
1. para11ax_mission { operation: "new" }
2. retain returned workspace
3. para11ax_mission { operation: "profile_set", workspace: <returned>, payload: {...} }
4. retain the new returned workspace
5. continue relevance -> hunt_build -> kql_validate -> result_analyze -> servicenow/export
```

Domain Investigation example:

```text
1. para11ax_domain_investigation { action: "build", enrichment: <canonical-domain-evidence-v2> }
2. retain returned artifact
3. para11ax_domain_investigation { action: "surface_import", artifact: <returned>, records: [...] }
4. retain returned artifact
5. optionally vulnerability_import
6. call show / report / stix / handoff with the current artifact
```

Investigations and cases follow the same state-in/state-out pattern. KQL is validated/projected, not executed. ServiceNow-ready output is projected, not submitted automatically.

## Registered-command boundary

`para11ax_command` resolves exact IDs from the registered command catalog. Remote policy denies browser-session-only commands, local-admin, filesystem, credential-template and other host-local effects. Unknown IDs do not fall back to arbitrary shell execution.

Intentionally local-only operations include setup, repair, release verification, local provider probes, environment templates, filesystem report compilation and report diff operations.

## Safety boundary

MCP does not expose:

- arbitrary host shell execution;
- caller-selected provider destinations or arbitrary HTTP;
- arbitrary filesystem paths;
- environment-secret values;
- credential persistence;
- provider host/method/credential overrides;
- automatic KQL execution;
- automatic ServiceNow submission;
- automatic Evidence v2 promotion of User Scanner/Shodan/Swarm context;
- hosted active surface discovery or vulnerability scanning through Domain Investigation.

Provider and OSINT work continues through existing fixed-host policies, timeouts, response limits, provenance, parser semantics and gateway authentication.

## Error semantics

Protocol errors use JSON-RPC errors. Tool failures are bounded MCP results with `isError: true`. Provider-specific errors are normalized by the underlying handler. A successful HTTP exchange is not proof of complete evidence coverage; batch callers inspect per-item `ok|partial|error` and enrichment limitations.

`GET /mcp` is expected to return `405 Method Not Allowed` with `Allow: POST`. The live route is `Cache-Control: no-store` and retains hardened response headers.

## Proof-state rules

Do not collapse these claims:

- **implemented**: code/tool exists;
- **CI-proven**: exact SHA passed repository gates;
- **deployment-proven**: exact SHA is READY in production;
- **transport-proven**: `/mcp` behaves correctly at protocol level;
- **OAuth-proven**: authorization/token exchange works;
- **credential-capability-proven**: a protected call actually reaches and succeeds for the relevant provider/worker/entitlement;
- **ChatGPT-connected**: that particular client/session can dispatch protected tools.

A successful token exchange with no subsequent `/mcp` request is a client/session binding issue, not proof of a PARA11AX backend failure. A live `/mcp` route does not prove every tier-3 provider or third-party entitlement.

## Related documentation

- [`README.md`](../README.md)
- [`API.md`](API.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`DOMAIN-INVESTIGATION.md`](DOMAIN-INVESTIGATION.md)
- [`PROVIDERS.md`](PROVIDERS.md)
- [`IDENTITY-OSINT.md`](IDENTITY-OSINT.md)
- [`GREYNOISE-SWARM.md`](GREYNOISE-SWARM.md)
- [`OPERATIONS.md`](OPERATIONS.md)
- [`SECURITY-CONTROLS.md`](SECURITY-CONTROLS.md)
- [`THREAT-MODEL.md`](THREAT-MODEL.md)
- [`CODE-REVIEW-2026-09-13.md`](CODE-REVIEW-2026-09-13.md)

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
