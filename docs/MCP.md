<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### MCP control plane

PARA11AX exposes its functional analyst surface through one authenticated remote Model Context Protocol endpoint at:

```text
https://para11ax.vercel.app/mcp
```

The MCP endpoint is a control plane over existing PARA11AX domain logic. It does **not** create a second implementation of enrichment, User Scanner, Shodan, GreyNoise Swarm, Mission Workspace, Investigation Workspace, cases, reports, or registered commands. Each MCP tool delegates into the same bounded validators/handlers used by the REST, Web, and CLI surfaces.

The transport implements the stateless `2026-07-28` profile and retains a bounded `2025-06-18` initialize compatibility response. Repository, deployment, live-credential, and ChatGPT-connection proof remain separate states tracked in [`OPERATIONS.md`](OPERATIONS.md).

#### Authentication and transport

Protocol discovery is public so ChatGPT can initialize and inspect the 13 tool descriptors before account linking. Public methods are limited to `server/discover`, `initialize`, `notifications/initialized`, `ping`, and `tools/list`; they execute no PARA11AX capability. Every tool declares:

```json
{"type":"oauth2","scopes":["para11ax:use"]}
```

Tool execution accepts either a ChatGPT-issued OAuth session token from the PARA11AX authorization bridge or the existing gateway bearer used by trusted non-OAuth clients:

```text
Authorization: Bearer <PARA11AX_TOKEN>
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
```

ChatGPT discovers and runs the authorization-code + PKCE flow through:

```text
GET  /.well-known/oauth-protected-resource
GET  /.well-known/oauth-protected-resource/mcp
GET  /.well-known/oauth-authorization-server
GET  /oauth/authorize
POST /oauth/authorize
POST /oauth/token
```

The authorization server accepts the fixed ChatGPT Client ID Metadata Document, exact stable ChatGPT redirect URI, `S256` PKCE, the exact `https://para11ax.vercel.app/mcp` resource, and the `para11ax:use` scope. The consent page validates the existing gateway access token without echoing or persisting it. The exchanged access token is signed, time-bounded, scope-bound, audience-bound to `/mcp`, and invalidated when the gateway secret rotates. The gateway secret itself is never returned to ChatGPT.

An unauthenticated tool call returns the MCP `_meta["mcp/www_authenticate"]` challenge required to open ChatGPT's linking UI. Non-tool authentication failures use HTTP `401` with the same protected-resource metadata challenge.

Modern requests also use the protocol routing headers enforced by the transport:

```text
Mcp-Method: <json-rpc method>
Mcp-Name: <tool name>   # required for tools/call
```

`Mcp-Method` must match the JSON-RPC method. For `tools/call`, `Mcp-Name` must match `params.name`. Mismatches fail closed with a protocol error. Successful modern responses use `resultType: "complete"`; discovery/list responses publish bounded private cache hints.

The endpoint is stateless. Mission, investigation, and analyst-case state is returned to the client and must be supplied on the next related call. No hidden cross-user workflow state is persisted by `/mcp`.

#### Discovery

The canonical modern discovery sequence is:

```text
server/discover
  -> tools/list
  -> tools/call
```

`server/discover` returns the supported protocol version, server identity, capabilities, and private TTL hints. `tools/list` returns the grouped PARA11AX tools, schemas, annotations, and per-tool OAuth policy. The MCP tool catalog is the authoritative remote capability inventory; browser-only presentation controls and local-administration commands are intentionally absent.

#### Functional surface

| Tool | PARA11AX capability | Authority / side effect |
| --- | --- | --- |
| `para11ax_capabilities` | MCP catalog, registered safe commands, authenticated gateway health/status/meta | read-only |
| `para11ax_enrich` | Evidence v2 single-observable enrichment | read-only external lookup |
| `para11ax_batch` | bounded 1..20 observable batch enrichment | read-only external lookup |
| `para11ax_provider` | one registered provider through the provider gateway | read-only external lookup |
| `para11ax_shodan` | bounded Shodan operator surface | read-only external lookup; some operations can consume query credits |
| `para11ax_swarm` | GreyNoise Project Swarm search/get/export/unique/timeseries/diff | read operations plus explicit bounded export semantics |
| `para11ax_user_scan` | isolated email/username OSINT scanner | active OSINT / open-world lookup |
| `para11ax_stix` | deterministic STIX 2.1 generation from PARA11AX enrichment | read-only projection |
| `para11ax_mission` | profile/context/relevance/hunt/KQL/result/ServiceNow mission workflow | explicit client-carried state mutation |
| `para11ax_investigation` | Investigation Workspace v2 create/status/mutate/report/import/export | explicit client-carried state mutation |
| `para11ax_case` | portable analyst case create/note/pin/capture/graph/diff/export | explicit client-carried state mutation |
| `para11ax_report` | deterministic report render/quality/manifest projections | read-only projection |
| `para11ax_command` | exact registered-command fallback for server-safe commands | policy-dependent registered operation |

This is **functional parity**, not UI mirroring. Terminal theme/audio, volatile login UI, focus/history controls, local download buttons, and other browser cosmetics are not remote analyst capabilities and are not modeled as MCP tools.

#### High-value examples

Identity OSINT through the actual User Scanner:

```json
{
  "name": "para11ax_user_scan",
  "arguments": {
    "scanType": "username",
    "target": "example_handle"
  }
}
```

```json
{
  "name": "para11ax_user_scan",
  "arguments": {
    "scanType": "email",
    "target": "analyst@example.com"
  }
}
```

The User Scanner result is an investigative lead, not proof of identity or compromise. Apply the entity-resolution rules in [`IDENTITY-OSINT.md`](IDENTITY-OSINT.md) and the passive search layer in [`GOOGLE-DORKING.md`](GOOGLE-DORKING.md).

Evidence enrichment:

```json
{
  "name": "para11ax_enrich",
  "arguments": {
    "indicator": "203.0.113.10",
    "profile": "standard"
  }
}
```

Mission state round trip:

```text
1. para11ax_mission { operation: "new" }
2. retain returned workspace
3. para11ax_mission { operation: "profile_set", workspace: <returned>, payload: {...} }
4. retain the new returned workspace
5. continue relevance -> hunt_build -> kql_validate -> result_analyze -> servicenow/export
```

Investigations and cases follow the same explicit state-in/state-out model. This makes serverless invocations reproducible and prevents later calls from depending on hidden process memory.

#### User Scanner + dorking OSINT route

The preferred identity workflow is:

```text
authorised identifier
  -> defensive exact-identifier dorks / passive indexed discovery
  -> para11ax_user_scan
  -> candidate account/profile/social leads
  -> de-duplicate and reject collisions
  -> independent public-source corroboration
  -> explicit operator-context capture
  -> finding / remediation / re-test
```

Dorking and User Scanner are complementary. Search engines improve historical/indexed recall; User Scanner improves structured platform/account recall. Neither is a truth source and neither automatically becomes Evidence v2.

#### Registered-command parity

`para11ax_command` resolves exact IDs from the same registered command catalog used by PARA11AX. The remote policy denies commands that are browser-session-only or require filesystem/local-admin effects. This gives MCP broad functional parity without turning PARA11AX into a shell or arbitrary execution service.

Examples of intentionally local-only operations include setup, repair, release verification, local provider probes, environment templates, filesystem report compilation, and report diff operations.

#### Safety boundary

The MCP endpoint does not expose:

- arbitrary host shell execution;
- arbitrary outbound HTTP or caller-selected provider destinations;
- arbitrary filesystem paths;
- environment-secret values;
- credential persistence;
- provider host/method/credential overrides;
- automatic KQL execution;
- automatic ServiceNow submission;
- automatic Evidence v2 promotion of User Scanner/Shodan/Swarm operator context.

Provider and OSINT work continues through existing PARA11AX validators, fixed-host policies, timeouts, response limits, circuit breakers, provenance, and gateway authentication. Local-admin/filesystem commands remain unreachable over MCP even when a similarly named local CLI operation exists.

#### Error and cache semantics

Protocol errors use JSON-RPC errors. Tool execution failures are returned as MCP tool results with `isError: true` and a bounded safe message. Provider-specific errors remain normalized by the underlying PARA11AX handler. The existing REST catch-all remains fail closed and is not used as an MCP dispatcher.

`GET /mcp` is expected to return `405 Method Not Allowed` with `Allow: POST`. The live route is `Cache-Control: no-store` and uses the same hardened response-header posture as the REST gateway.

#### Proof-state rules

Do not collapse these claims:

- **implemented** — code/tool exists in the repository;
- **CI-proven** — exact SHA passed Tooling smoke/CodeQL;
- **deployment-proven** — Vercel reports that exact SHA as READY;
- **transport-proven** — `/mcp` responds with the expected MCP method/header behavior;
- **credential-capability-proven** — an authenticated tool call actually succeeds for the relevant configured provider/worker/entitlement;
- **ChatGPT-connected** — the MCP server has been installed/configured as a ChatGPT plugin/connector and authentication succeeds from that client.

A live `/mcp` endpoint does not by itself prove that every credentialed provider, User Scanner worker, GreyNoise entitlement, or third-party MCP client is configured.

#### Related documentation

- [`README.md`](../README.md) — product/operator overview.
- [`API.md`](API.md) — REST + MCP transport inventory.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — trust boundaries and delegation model.
- [`IDENTITY-OSINT.md`](IDENTITY-OSINT.md) — User Scanner/entity-resolution workflow.
- [`GOOGLE-DORKING.md`](GOOGLE-DORKING.md) — defensive indexed-discovery playbook.
- [`OPERATIONS.md`](OPERATIONS.md) — deployment/acceptance proof states.
- [`SECURITY-CONTROLS.md`](SECURITY-CONTROLS.md) — security-control mapping.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — MCP/remote-tool threat boundary.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
