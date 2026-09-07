<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### API

All responses are JSON unless a documented human-facing error representation is explicitly negotiated. Production clients should use HTTPS. The gateway bearer is `Authorization: Bearer <PARA11AX_TOKEN>`.

#### Canonical Evidence v2 workflows

Supported indicator types are `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, and `certificate`. Certificate input is explicit: `cert-sha256:<64-hex>`. Fixed profiles are `fast`, `standard`, and `full`; callers cannot select arbitrary Evidence v2 providers.

Profile admission and execution priority are separate. Admitted providers are ordered by **Provider Value Scheduler v1.0**. For the current IP reference workflow, 24 admitted providers retain a 48-call ceiling (maximum two attempts per provider), maximum concurrency 4, and the 20-second request deadline. Scheduler ordering does not add or suppress providers based on returned evidence.

Email/username User Scanner operations, native Shodan commands, and GreyNoise Project Swarm session/workspace operations are separate analyst utilities. They do not become canonical Evidence v2 workflow types and do not automatically replace or promote into the current Evidence v2 result.

#### Route inventory

- `GET /api/para11ax/meta` — public static capabilities and hard limits, including scheduler policy metadata where applicable.
- `GET /api/para11ax/health` — bearer-protected readiness; `Cache-Control: no-store`.
- `GET /api/para11ax/status` — bearer-protected count-only runtime state; `Cache-Control: no-store`.
- `POST /api/para11ax/enrich` — one canonical indicator.
- `POST /api/para11ax/batch` — 1–20 indicators; max 3 active indicators / 200 provider calls.
- `POST /api/para11ax/stix` — enrich then export bounded STIX 2.1.
- `POST /api/para11ax/user-scanner` — isolated bounded email/username active OSINT.
- `POST /api/para11ax/shodan` — bounded authenticated native Shodan operator commands.
- `POST /api/para11ax/swarm` — bounded authenticated GreyNoise Project Swarm search, session detail, pivots, Workspace Diff, and explicit single-session export.

Unknown `/api/para11ax/*` paths fail closed.

#### `POST /api/para11ax/enrich`

```json
{"indicator":"203.0.113.10","profile":"standard"}
```

Normalized `ok`/`partial` results retain authoritative Evidence v2 and add deterministic analytical projections. The IP reference path can include top-level `intelligence` from **Intelligence Kernel v1.0**, followed by kernel-aware `decision` and bounded `guidance`; Evidence Graph v1.0 remains an explicit-evidence projection and does not ingest Kernel-derived relationships as evidence.

Representative trimmed IP envelope:

```json
{
  "schemaVersion": "2.0",
  "indicator": "203.0.113.10",
  "type": "ip",
  "profile": "standard",
  "status": "ok",
  "evidence": [],
  "relationships": [],
  "correlation": {},
  "intelligence": {
    "schemaVersion": "1.0",
    "type": "ip",
    "evidenceStrength": {"level": "moderate"},
    "analystPriority": {"level": "investigate"},
    "coverageImpact": {"level": "none"}
  },
  "decision": {},
  "evidenceGraph": {"schemaVersion": "1.0", "nodes": [], "edges": []},
  "guidance": {"schemaVersion": "1.0"}
}
```

`intelligence` is deterministic derived context, not Evidence v2. It may summarize evidence strength, source diversity, corroboration independence, contradiction severity, temporal relevance, explicit one-hop pivots, threat context, hunt relevance, coverage impact, analyst priority, limitations and trace rule IDs. Kernel projection failure is isolated: usable Evidence v2 remains valid and the unavailable projection is surfaced as a limitation rather than converted into an enrichment failure.

Non-IP workflows remain compatible with their established correlation/decision path until an explicit observable policy adopts the Kernel contract. Error envelopes do not manufacture `intelligence`, Evidence Graph or Guidance projections.

#### `POST /api/para11ax/batch`

```json
{"indicators":["192.0.2.44","evil.example"],"profile":"standard"}
```

Limits: 1..20 strings, max 3 active indicators, max 200 provider calls globally, one shared deadline, canonical de-duplication, and no provider override.

#### `POST /api/para11ax/stix`

Uses the same single-indicator request contract as `/enrich`. The gateway enriches first and then maps the bounded result to STIX 2.1; caller-supplied enrichment objects are rejected. Intelligence Kernel-derived conclusions do not become new STIX evidence or attribution facts.

#### `POST /api/para11ax/user-scanner`

Separate active-OSINT capability used by the `user-scanner` command and `osint` / `identity` aliases.

```json
{"scanType":"username","target":"kaifcodec","crossScan":false,"noNsfw":true}
```

The caller cannot select the worker URL, proxy, concurrency, arbitrary destination or timeout. Output remains separate from Evidence v2 and Intelligence Kernel reasoning.

#### `POST /api/para11ax/shodan`

Bearer required. The browser sends a normalized Shodan operator request to the same-origin route. The gateway reads `SHODAN_API_KEY` server-side and contacts only `https://api.shodan.io`.

Approved shell commands and equivalent request shapes:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

```json
{"command":"host","target":"8.8.8.8"}
```

```json
{"command":"search","query":"product:FortiGate country:HU"}
```

```json
{"command":"count","query":"port:443 country:HU"}
```

```json
{"command":"stats","query":"product:nginx","facets":"country:20,org:10"}
```

```json
{"command":"domain","target":"example.com"}
```

```json
{"command":"info"}
```

Unknown fields and unsupported commands/options are rejected. Caller-selected URLs, pages, methods, credentials and arbitrary Shodan operations are not accepted. `shodan download` is disabled.

Response envelope:

```json
{
  "requestId":"<uuid>",
  "source":"shodan",
  "command":"stats",
  "input":{"query":"product:nginx","facets":"country:20,org:10"},
  "creditImpact":"none",
  "data":{},
  "durationMs":42
}
```

`creditImpact` is explicit:

- `host` — `none`
- `count` — `none`
- `stats` — `none`
- `info` — `none`
- `domain` — `consumes_query_credit`
- `search` — `may_consume_query_credit`

Search is first-page only. Search results and host-service lists are bounded; large raw banners/service bodies are removed before the response reaches the browser. Shodan operator output is terminal/operator context and leaves the current Evidence v2 enrichment and `intelligence` projection unchanged.

#### `POST /api/para11ax/swarm`

Bearer required. The browser sends only normalized Swarm operations to the same-origin route. The gateway reads `GREYNOISE_API_KEY` server-side, contacts only `https://api.greynoise.io`, refuses redirects, and does not accept caller-selected URLs, methods, headers, credentials, or arbitrary GreyNoise operations.

Approved operations and representative request shapes:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <field> [--scope workspace|demo] [--query <lucene>] [--include-counts]
swarm timeseries --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--field <field>] [--size <1..100>] [--interval <auto|1s|1m|1h|1d>]
swarm diff --query <GNQL> [--source personal|community|greynoise] [--target personal|community|greynoise] [--mode source-only|both|all] [--size <1..100>] [--next-token <token>]
swarm export <session-id> <pcap|raw-source|raw-destination>
```

```json
{"command":"search","scope":"workspace","startTime":"2026-09-05T00:00:00Z","endTime":"2026-09-06T00:00:00Z","query":"classification:malicious","page":1,"pageSize":25}
```

```json
{"command":"get","scope":"demo","sessionId":"<session-id>"}
```

```json
{"command":"unique","scope":"workspace","startTime":"2026-09-05T00:00:00Z","endTime":"2026-09-06T00:00:00Z","field":"source.ip","includeCounts":true}
```

```json
{"command":"timeseries","scope":"workspace","startTime":"2026-09-05T00:00:00Z","endTime":"2026-09-06T00:00:00Z","query":"destination.port:443","field":"classification","size":10,"interval":"1h"}
```

```json
{"command":"diff","query":"classification:malicious","sourceWorkspace":"personal","targetWorkspace":"greynoise","mode":"source-only","size":10}
```

```json
{"command":"export","scope":"workspace","sessionId":"<session-id>","type":"pcap"}
```

Search/pivot ranges must be valid explicit ISO-8601 intervals with `startTime < endTime`. Session Lucene and Workspace Diff GNQL text are capped at 2,048 printable characters. Search page size is 1..100, page number is 1..10,000, timeseries group size is 1..100, and pivot fields/intervals come from fixed allowlists. Workspace Diff accepts only `personal`, `community`, and `greynoise`, requires different source/target aliases, caps result size at 100, and caps opaque `nextToken` values at 4,096 printable characters. JSON results and each single-session binary export are capped at 4 MiB. Bulk session export and arbitrary workspace UUIDs are not exposed.

`scope=workspace` uses the sensor-backed workspace session dataset and requires the applicable GreyNoise Sensors entitlement. `scope=demo` uses the GreyNoise demo session dataset and requires the applicable Swarm entitlement. Workspace Diff uses its own approved workspace aliases instead of the session `scope` parameter. Demo export is rejected locally before upstream egress. PARA11AX does not infer or advertise a production entitlement merely because a key is configured.

Successful `search`, `get`, `unique`, `timeseries`, and `diff` responses are bounded operator context. They can be explicitly captured with `investigation capture operator`; that capture does not manufacture or modify Evidence v2, provider corroboration, ATT&CK mapping, maliciousness, or analyst disposition. `export` is an explicit browser download and does not replace the current operator result.

Full operator contract: [`GREYNOISE-SWARM.md`](GREYNOISE-SWARM.md).

#### Common errors

- `400` — invalid request/indicator/profile/batch, invalid Shodan command/target/query/facets, or rejected Swarm command/range/query/pivot/diff/export shape.
- `401 unauthorized`.
- `405 method_not_allowed`.
- `413 payload_too_large`.
- `415 unsupported_media_type`.
- User Scanner uses controlled `502`/`503`/`504` worker errors.
- Shodan missing configuration fails closed with controlled `503`; upstream rate limiting is returned explicitly rather than converted into empty/negative evidence.
- Swarm missing configuration, authentication/entitlement rejection, rate limiting, missing session, malformed/oversized upstream data, timeout, or transport failure remains an explicit operational error and is never converted into threat evidence.

#### Security invariants

Caller input never selects arbitrary provider hosts, Shodan hosts, GreyNoise hosts, worker hosts, methods, provider secrets, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, or arbitrary adapters. Evidence v2 provider egress remains fixed through `safeFetch`. Provider Value Scheduler v1.0 and Intelligence Kernel v1.0 add no new egress, credential, persistence or dependency surface and use no LLM. User Scanner, Shodan, and GreyNoise Swarm use separate bounded authenticated routes with server-configured fixed destinations. See `THREAT-MODEL.md`, `SECURITY-CONTROLS.md`, `SHODAN-SHELL.md`, and `GREYNOISE-SWARM.md`.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>