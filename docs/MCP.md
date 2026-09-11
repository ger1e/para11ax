<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### MCP control plane

PARA11AX exposes an authenticated remote Model Context Protocol endpoint at `/mcp` so an MCP client can operate the platform's functional analyst surface without receiving host-shell, arbitrary-fetch, arbitrary-filesystem, or local-admin access.

#### Endpoint and authentication

Production endpoint: `https://para11ax.vercel.app/mcp`

All MCP requests require the same bearer secret used by the PARA11AX gateway:

```text
Authorization: Bearer <PARA11AX_TOKEN>
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
```

The server is stateless. Mission, investigation, and analyst-case state is returned to the client and must be supplied on the next related call. No cross-user workflow state is persisted by the MCP endpoint.

The canonical protocol surface is the stateless `2026-07-28` profile (`server/discover`, `tools/list`, `tools/call`). A bounded `initialize` compatibility response is retained for clients that still negotiate the earlier `2025-06-18` profile.

#### Functional surface

The server publishes these grouped MCP tools:

| Tool | PARA11AX capability |
| --- | --- |
| `para11ax_capabilities` | MCP catalog, registered safe commands, authenticated gateway health/status/meta |
| `para11ax_enrich` | Evidence v2 single-observable enrichment |
| `para11ax_batch` | bounded 1..20 observable batch enrichment |
| `para11ax_provider` | one registered provider through the provider gateway |
| `para11ax_shodan` | bounded Shodan operator surface |
| `para11ax_swarm` | GreyNoise Project Swarm search/get/export/unique/timeseries/diff |
| `para11ax_user_scan` | isolated email/username OSINT scanner |
| `para11ax_stix` | deterministic STIX 2.1 generation |
| `para11ax_mission` | profile/context/relevance/hunt/KQL/result/ServiceNow mission workflow |
| `para11ax_investigation` | Investigation Workspace v2 create/status/mutate/report/import/export |
| `para11ax_case` | portable analyst case create/note/pin/capture/graph/diff/export |
| `para11ax_report` | deterministic report render/quality/manifest projections |
| `para11ax_command` | exact registered-command fallback for server-safe commands |

This is functional parity rather than UI mirroring. Browser cosmetics such as terminal theme/audio, volatile login UI, and local download controls are not modeled as remote MCP tools because they do not add analyst capability.

#### Safety boundary

`para11ax_command` resolves exact ids from the same registered command catalog used by PARA11AX. The MCP policy denies commands that are browser-session-only or require `filesystem` / `local-admin` effects. Setup, repair, release verification, local provider probes, environment templates, filesystem report compilation, and report diff operations therefore remain local-only.

The MCP endpoint does not expose an arbitrary shell, arbitrary outbound HTTP, arbitrary filesystem paths, environment-secret values, or credential persistence. Provider and OSINT work continues through existing PARA11AX validators, fixed-host policies, timeouts, response limits, circuit breakers, provenance, and gateway authentication.

#### Stateless workflow example

A mission begins with `para11ax_mission { operation: "new" }`. The response contains `workspace`; supply that returned object to subsequent mission calls. Investigations and cases follow the same explicit state-handle pattern. This makes serverless invocations reproducible and prevents a later invocation from depending on hidden process memory.

#### Failure semantics

Protocol errors use JSON-RPC errors. Tool execution failures are returned as MCP tool results with `isError: true` and a bounded safe message. Provider-specific errors remain normalized by the underlying PARA11AX handler. The existing REST catch-all remains fail closed and is not used as an MCP dispatcher.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
