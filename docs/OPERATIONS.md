<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Operations

#### Acceptance and proof states

Keep these states separate:

1. **Repository-proven** — exact source SHA passes repository invariants, dependency/public-release checks, Node tests, Maltego tests, Python compilation, shell/ShellCheck, and PowerShell parsing.
2. **CI-proven** — GitHub Actions reports the required checks for that exact SHA. `Tooling smoke` is the branch-required gate; CodeQL is also required by the PARA11AX QA/release process.
3. **Configured** — required runtime secrets/environment values exist. Source code cannot prove this.
4. **Deployment-proven** — Vercel metadata reports the expected exact Git SHA and `READY` state.
5. **Live-public-proven** — public unauthenticated routes return expected status/content on that deployment.
6. **Credential/provider-proven** — authenticated health/status/provider probes were actually executed against the exact deployment.
7. **MCP-transport-proven** — `/mcp` responds with the expected method/protocol/header behavior on the exact deployment.
8. **MCP-client-connected** — a specific MCP client is configured/authenticated and a tool call succeeds from that client.
9. **User-Scanner-wired** — the isolated worker is deployed/configured and an authorized scan succeeds through the PARA11AX REST/Web/MCP path.
10. **Shodan-wired** — `SHODAN_API_KEY` is configured and an authorized bounded Shodan operation succeeds through the existing handler, directly or via MCP.
11. **GreyNoise-Swarm-wired** — `GREYNOISE_API_KEY` is configured and an authorized bounded Swarm read succeeds for the intended scope through the existing handler, directly or via MCP. Workspace/demo entitlement and export entitlement remain separate upstream facts.

Do not collapse these into one “production verified” claim.

#### Current verified production baseline — 2026-09-11

The full PARA11AX MCP control plane merged through PR #226 to protected `main` as:

```text
974fd1760e44a0301f05fb0a8d263528c4273a0e
```

The exact PR head passed both Tooling smoke and CodeQL before merge. The protected `main` push also passed Tooling smoke. Vercel deployed the exact merge SHA as production deployment:

```text
dpl_8fXXAsbDXuiB2vtqDWKCHaJs8J7w
source SHA: 974fd1760e44a0301f05fb0a8d263528c4273a0e
state: READY
canonical alias: para11ax.vercel.app
```

A public live probe of `/mcp` returned the expected fail-closed method behavior: `GET /mcp` -> `405 Method Not Allowed`, `Allow: POST`, `MCP-Protocol-Version: 2026-07-28`, `Cache-Control: no-store`, plus the hardened response-header baseline. That proves deployment and MCP transport presence. It does **not** by itself prove an external MCP client connection, gateway-bearer possession by that client, User Scanner worker wiring, every provider credential, or GreyNoise/Shodan entitlement/readiness.

The same deployed source includes Provider Value Scheduler v1.0, Intelligence Kernel v1.0, User Scanner, Shodan, GreyNoise Project Swarm, Mission Workspace, Investigation Workspace v2, cases/reports, defensive identity-OSINT documentation, and the MCP control plane. Re-check GitHub/Vercel metadata before making a future “current production” claim.

#### Historical Scheduler / Kernel repository baseline — 2026-08-30

Retain this record as historical release provenance, not as the current production state. The Unified Intelligence Kernel / Provider Value Scheduler release merged to protected `main` as:

```text
11d7b861d9f626c45f44c138c8d72cee9493efdf
```

That exact SHA passed the historical hosted gates recorded in `QA-REPORT.md` (`Tooling smoke 1374` and `CodeQL 962`). It established Provider Value Scheduler v1.0 and the IP-reference Intelligence Kernel v1.0 without adding providers, hosts, dependencies, egress, credential reads, or persistence surfaces.

At that historical point a Vercel **build-rate limit** prevented immediate production advancement. That event is retained because it is the canonical example of why repository/CI proof and deployment proof must stay separate. It has been superseded as the current runtime baseline by the 2026-09-11 MCP production deployment above.

#### MCP control-plane operations

Reference topology:

```text
MCP client
  -> https://para11ax.vercel.app/mcp
  -> PARA11AX_TOKEN bearer authentication
  -> MCP protocol/header validation
  -> grouped MCP tool
  -> existing PARA11AX handler / pure domain logic / registered server-safe command
  -> structured MCP result
```

Current protocol profile:

```text
MCP-Protocol-Version: 2026-07-28
Mcp-Method: <JSON-RPC method>
Mcp-Name: <tool name>   # tools/call only
```

The transport is stateless. Mission/investigation/case state is explicit state-in/state-out; the server does not persist hidden cross-user workflow sessions. `para11ax_command` uses the shared registered command catalog but denies browser-session-only and filesystem/local-admin effects.

Operational MCP verification should distinguish:

```text
route exists
-> transport conforms
-> bearer authentication works
-> tools/list works
-> selected tool succeeds
-> selected provider/worker/entitlement succeeds
```

A 401 on an authenticated-required call proves the route is protected, not broken. A successful `tools/list` proves the MCP catalog, not all credentialed dependencies. A successful User Scanner/Shodan/Swarm call proves only that specific bounded path and current external dependency state.

#### Historical GreyNoise integration baseline — 2026-09-06

Project Swarm integration landed in three source changes before the MCP control plane:

- PR #207 / `dfb3ef854885321f175ef588d5b8398c86baedc2` — authenticated GreyNoise v3 IP lookup with bounded Project Swarm workspace labels.
- PR #208 / `76030561a6b4b78131d6a32f5084e0620535aad7` — Swarm session `search`, `get`, and explicit single-session `export`.
- PR #209 / `ec3cac395693cc448a7bfada5ed7cd6c9ff68000` — allowlisted `unique` and `timeseries` pivots plus explicit Investigation Workspace operator capture for Swarm read results.

These source/CI facts do not prove a production GreyNoise credential or account entitlement. MCP now delegates `para11ax_swarm` to the same bounded Swarm handler; it does not create additional GreyNoise access.

#### Provider scheduling operations

Provider Value Scheduler v1.0 changes deterministic attempt order among already-admitted providers. It does not alter profile admission.

Current IP reference invariants:

- 24-provider IP workflow;
- 48-call ceiling (24 × maximum two attempts);
- max provider concurrency 4;
- request deadline 20 seconds;
- every admitted provider remains scheduled;
- scheduler metadata failure falls back deterministically;
- no evidence-dependent source suppression;
- no LLM/runtime learning/adaptive ranking.

Scheduler metadata exposed by capability/meta surfaces is audit metadata. It must not expose credentials or be described as a threat score.

#### Intelligence Kernel operations

Intelligence Kernel v1.0 is an in-process deterministic derived-context projection over existing normalized evidence/correlation/coverage. Current code support is IP-reference only.

Operational invariants:

- Evidence v2 remains authoritative.
- Kernel output is derived context, not provider evidence.
- no provider/network call, secret/environment read, persistence or new dependency;
- no LLM or adaptive runtime model;
- explicit one-hop pivots only from normalized relationships;
- observation timestamps drive temporal reasoning; missing time stays unknown;
- provider failures/skips affect coverage, never become benign/negative threat evidence;
- Kernel projection failure is isolated as `intelligence_projection_unavailable` and does not discard otherwise-valid Evidence v2;
- Decision Support and Guidance retain guarded legacy fallback behavior when Kernel data is absent/incompatible.

MCP does not alter these invariants. `para11ax_enrich`, `para11ax_batch`, `para11ax_provider`, and `para11ax_stix` delegate into the same evidence/analysis path.

#### Local/full repository verification

From a clean checkout of exact `main`:

```powershell
git fetch origin
git checkout main
git pull --ff-only
npm run check
cd maltego
python3 -m unittest discover -s tests -v
cd ..
python3 -m compileall -q maltego
python3 -m compileall -q workers/user-scanner
```

`npm run check` includes repository invariants, public-release audit, full Node tests and executable documentation-contract checks.

#### Documentation contract maintenance

Externally meaningful canonical facts must not drift silently. Current checks cover:

- all nine Evidence v2 workflow types;
- canonical 38-provider fabric;
- Provider Value Scheduler v1.0 and IP scheduling invariants;
- Evidence Schema v2 / Intelligence Kernel v1.0 / Evidence Graph v1.0 / Guidance v1.0 boundaries;
- REST route inventory and fail-closed behavior;
- MCP `/mcp` route presence, current protocol version, tool catalog, routing-header checks, stateless behavior, and local-admin/filesystem denial;
- User Scanner aliases/boundary/environment names;
- Shodan commands, endpoint, fixed upstream, key name, credit behavior, first-page search, Evidence v2 isolation and disabled `download`;
- GreyNoise Project Swarm `search`, `get`, `unique`, `timeseries`, `diff`, `export`, scope/entitlement distinction, 4 MiB ceilings, fixed upstream, and Evidence v2 isolation;
- Maltego workflow/certificate semantics;
- canonical production identity;
- GER1E-normalized README SVG sizing/typography;
- changelog/QA coverage for externally meaningful capabilities.

When a canonical source changes, update the relevant documentation and drift test in the same PR. Do not weaken the test merely to preserve stale prose.

#### Hosted CI and deployment boundary

This public repository runs one bounded Ubuntu `Tooling smoke` job for pull requests targeting `main`, pushes to `main`, and manual dispatch. CodeQL runs separately for JavaScript/TypeScript and Python analysis.

Vercel Git deployment is narrower than CI. A protected verified merge to `main` is not production acceptance by itself. Accept production only when deployment metadata reports that exact `main` SHA in `READY` state. A quota/build-rate limit or rejection is a deployment failure state, not a code/test failure and not permission to pretend the previous deployment contains the new code.

#### User Scanner hosted wiring

Reference topology:

```text
Web / MCP
  -> existing bounded User Scanner handler
  -> PARA11AX_USER_SCANNER_URL
  -> isolated User Scanner worker
```

Main project configuration:

```text
PARA11AX_USER_SCANNER_URL=https://user-scanner-kappa.vercel.app
PARA11AX_USER_SCANNER_TOKEN=<optional matching worker bearer>
```

Do not put worker credentials in tracked files, client JavaScript, screenshots, MCP examples, or documentation containing real values.

Identity investigations should use the documented route:

```text
authorised identity anchor
  -> defensive Google dorks / passive indexed discovery
  -> User Scanner
  -> collision rejection / independent corroboration
  -> explicit operator context
  -> finding / remediation / same-query re-test
```

See `IDENTITY-OSINT.md` and `GOOGLE-DORKING.md`.

#### Shodan analyst operations

Reference topology:

```text
Web / MCP
  -> bounded Shodan command handler
  -> SHODAN_API_KEY (server-side only)
  -> https://api.shodan.io
```

Production configuration:

```text
SHODAN_API_KEY=<server-side Shodan API key>
```

Approved commands:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

Operational guarantees:

- fixed upstream origin `https://api.shodan.io`;
- no client exposure of `SHODAN_API_KEY`;
- no caller-selected URLs, hosts, methods, pages, credentials, proxy routes, or arbitrary Shodan operations;
- search is first-page only;
- returned match/service arrays are bounded;
- large raw banners/service bodies are removed;
- `shodan download` is disabled;
- Shodan output stays operator context and leaves Evidence v2 / Intelligence Kernel state unchanged.

Credit classification:

- `host`, `count`, `stats`, `info` — no query credit;
- `domain` — consumes a query credit;
- `search` — may consume a query credit depending on Shodan plan/query behavior.

Treat quota/account state as time-sensitive operational state, not a repository fact.

#### GreyNoise Project Swarm operations

Reference topology:

```text
Web / MCP
  -> bounded Swarm command handler
  -> GREYNOISE_API_KEY (server-side only)
  -> fixed https://api.greynoise.io
```

Production configuration:

```text
GREYNOISE_API_KEY=<server-side GreyNoise API key>
GREYNOISE_WORKSPACE_LABELS=greynoise,community,personal   # optional canonical IP-lookup scope override
```

Approved operations:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> [--scope workspace|demo] [--query <lucene>] [--include-counts]
swarm timeseries --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--field <allowlisted-field>] [--size <1..100>] [--interval <auto|1s|1m|1h|1d>]
swarm diff --query <GNQL> [--source personal|community|greynoise] [--target personal|community|greynoise] [--mode source-only|both|all] [--size <1..100>] [--next-token <token>]
swarm export <session-id> <pcap|raw-source|raw-destination>
```

Operational guarantees:

- fixed `https://api.greynoise.io` upstream and server-side `GREYNOISE_API_KEY`;
- no arbitrary destination, method, headers, credentials, bulk export, pivot field, or response-size override;
- explicit valid time range required where documented;
- query text max 2,048 printable characters;
- search page size max 100; page max 10,000;
- timeseries size max 100 and interval fixed to the documented allowlist;
- JSON read results max 4 MiB; single-session binary exports max 4 MiB;
- bulk `/v3/sessions/export` is intentionally not exposed;
- `scope=workspace` depends on applicable Sensors entitlement;
- `scope=demo` depends on applicable Swarm entitlement and cannot export;
- read results may be explicitly captured as Investigation Workspace operator context, never automatic Evidence v2;
- export is explicit and does not become automatic investigation evidence.

See `GREYNOISE-SWARM.md` for the exact pivot field allowlist and upstream mapping.

#### Production smoke acceptance

Acceptance is against one exact source SHA. Verify deployment metadata first; reject a stale deployment.

Public QA can verify without a bearer:

- `GET /`;
- `GET /app/`;
- public `GET /api/para11ax/meta`;
- `GET /mcp` returns 405/`Allow: POST` with current MCP protocol/header posture;
- representative static/error routes;
- deployment metadata/source SHA.

Credential-bearing acceptance, only when explicitly authorized, adds:

- protected `/api/para11ax/health` and `/status`;
- MCP `server/discover` and `tools/list` with matching protocol/routing headers;
- one bounded `para11ax_enrich` or equivalent REST enrichment;
- one configured credentialed-source enrichment;
- for IP, confirm `intelligence.schemaVersion: "1.0"` only on a deployment whose source SHA includes Kernel v1;
- one bounded `para11ax_user_scan`/User Scanner operation when expected to be wired;
- `para11ax_shodan` with an approved no-query-credit operation such as info when appropriate;
- one non-export `para11ax_swarm` read for each scope whose entitlement is being claimed;
- one workspace export only when that export entitlement is intentionally being validated;
- no bearer/API-key reflection in response bodies or errors.

If an authorized bearer is not used, report authenticated health/status/provider/MCP tool execution/User Scanner/Shodan/GreyNoise Swarm readiness as **not proven by this QA pass** rather than failed or implicitly healthy.

#### Provider readiness

Use the sequential secret-safe provider probe in an authorized local environment:

```bash
para11ax providers probe --all
```

The Evidence v2 Shodan provider and Shodan operator handler are separate acceptance surfaces. The canonical Evidence v2 GreyNoise IP provider and GreyNoise Swarm session handler are also separate acceptance surfaces. MCP delegates to these surfaces; it does not merge their readiness states.

#### Maltego acceptance

Repository tests enforce parity between the nine server Evidence v2 workflow types and Maltego transforms. Certificate semantics remain explicit: `EnrichCertificate` adds `cert-sha256:` while `EnrichHash` retains file-hash semantics.

User Scanner, Shodan analyst operations, GreyNoise Swarm session operations, MCP tools, and Intelligence Kernel derived pivots are not silently added as new Maltego Evidence v2 transforms.

#### Browser-local workspace / MCP state acceptance

Cases, snapshots, diffs, exact typed sightings, and case graphs remain browser-local IndexedDB state when using the browser. Active-case state/authentication remain runtime-only. User Scanner, Shodan and GreyNoise Swarm read output are operator context; only explicit compatible Investigation Workspace actions record that context. Swarm packet/raw exports remain external outputs and are not automatically persisted/pinned as typed case evidence.

MCP does not access browser IndexedDB. `para11ax_mission`, `para11ax_investigation`, and `para11ax_case` return portable state and require the caller to send that state back for subsequent operations.

#### Secret handling

- Keep `.env*` except `.env.example` untracked.
- Store production secrets in Vercel/project secret storage, not Git.
- Rotate `PARA11AX_TOKEN` if exposed.
- Rotate `PARA11AX_USER_SCANNER_TOKEN` independently if enabled/exposed.
- Rotate `SHODAN_API_KEY` independently if exposed.
- Rotate `GREYNOISE_API_KEY` independently if exposed.
- Rotate affected provider credentials independently.
- Do not send raw queried indicators, identity targets, Swarm session payloads, packet data, or secrets to observability telemetry.
- Never embed the live gateway bearer in MCP documentation, screenshots, GitHub issues, or client-side source.

#### Failure behavior

Evidence v2 provider failures remain explicit, are not cached as negative evidence, and can yield partial results while successful providers continue. Scheduler budget/deadline skips remain coverage facts. Kernel projection failures do not transform provider/evidence state.

MCP protocol/header mismatch fails closed before tool dispatch. Tool execution errors remain bounded tool errors and do not convert failures into evidence. User Scanner gateway misconfiguration/worker failure/timeout use controlled errors. Shodan missing configuration fails closed; rate limiting remains explicit. GreyNoise Swarm missing configuration, entitlement/auth rejection, rate limiting, missing session, timeout, malformed/oversized response, or transport failure also stays operational. None of these states becomes benign/empty Evidence v2.

#### Parser / scheduler / Kernel / operator changes

When an Evidence v2 upstream schema changes: add a reproducing failing fixture, update minimally, increment parser version, regenerate manifest, update docs/drift guards, run full verification, and production-smoke the changed provider.

When scheduler descriptors/order change: update deterministic priority fixtures, capability metadata expectations, exact IP order/invariants, provider docs and release notes together. Admission/egress must remain separately reviewed.

When Intelligence Kernel rules/policy change: require TDD fixtures for evidence traceability, permutation determinism, failure isolation, compatibility fallbacks and report/Guidance behavior. A semantic change that can alter analyst priority/disposition requires an explicit version/release review.

When MCP changes: update runtime/conformance tests, `MCP.md`, README, API, architecture, operations, security/threat-model docs and release notes together. Tool additions must reuse bounded domain logic, declare accurate side effects, retain explicit state semantics where needed, and preserve the no-shell/no-arbitrary-fetch/no-local-admin boundary.

When Shodan operator contract changes: update runtime tests, `SHODAN-SHELL.md`, README, API/architecture/operations/security/threat-model docs and changelog together.

When GreyNoise Swarm operator contract changes: update runtime tests, `GREYNOISE-SWARM.md`, README, API/SHELL/architecture/operations/providers/security/threat-model/investigation docs and changelog together. Scope/entitlement claims, field allowlists, export semantics and Evidence v2 separation require explicit review.

#### Public release

Treat every tracked repository artifact as public. Run `npm run audit:public` and follow `PUBLIC-RELEASE-CHECKLIST.md` before release publication. `QA-REPORT.md` records proof boundaries; current external GitHub/Vercel state must still be read during verification.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>