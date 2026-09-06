<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### End-to-end enrichment example

This is a **sanitized structural example**, not captured production telemetry and not a claim about a live IOC. It uses the documentation-only address `203.0.113.10` so the flow can be understood without publishing sensitive or operational data.

#### 1. Request

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer <PARA11AX_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"203.0.113.10","profile":"standard"}' \
  https://<gateway>/api/para11ax/enrich
```

The caller supplies only an indicator and a fixed profile. It cannot select an upstream provider, host, method, header, provider credential or scheduler rank.

The classifier supports nine explicit workflow types: `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, and `certificate`. Certificate SHA-256 is explicit as `cert-sha256:<64-hex>`; a bare SHA-256 remains a file hash.

#### 2. Classification and admission

The gateway canonicalizes the example input as:

```json
{
  "indicator": "203.0.113.10",
  "type": "ip",
  "profile": "standard"
}
```

The IP workflow selects only statically registered providers admitted by the fixed profile. Missing credentials reduce coverage explicitly; they do not cause hidden fallback to an unregistered source.

#### 3. Provider Value Scheduler v1.0 and fixed egress

After admission, Provider Value Scheduler v1.0 deterministically orders the admitted adapters. The ordering is static metadata-driven and does not depend on evidence returned earlier in the same request.

The current **24-provider IP workflow** keeps a **48-call ceiling**: at most two attempts/provider, maximum four active providers, and a 20-second request deadline. The scheduler changes attempt order only; it does not add providers or destinations.

Each adapter executes through the central `safeFetch` boundary. The boundary enforces HTTPS only, exact allowlisted hosts, declared methods, no redirects, request/response ceilings, bounded timeout/retry behavior, and the existing concurrency ceiling. Upstream responses remain untrusted until the provider parser validates and normalizes them.

#### 4. Evidence v2 and typed correlation

A successful response uses Evidence Schema v2. The trimmed example below is illustrative; provider availability, observations, timings, hashes and counts vary by request.

```json
{
  "schemaVersion": "2.0",
  "gatewayVersion": "2.0.0",
  "requestId": "<bounded-correlation-id>",
  "indicator": "203.0.113.10",
  "type": "ip",
  "profile": "standard",
  "status": "ok",
  "providerSummary": {"ok": 3, "failed": 0, "skipped": 2, "cached": 0},
  "evidence": [],
  "relationships": [],
  "failures": [],
  "correlation": {
    "corroboration": [],
    "contradictions": [],
    "freshness": "unknown",
    "huntability": {"level": "<bounded-level>", "rationale": []}
  }
}
```

Evidence v2 is authoritative. Provider failures/skips remain coverage facts, never negative reputation evidence. Routing/registration context, Shodan/Censys exposure, GreyNoise scanner/noise context, certificate metadata, scanner activity, Tor-exit status, reputation, ransomware claims and ATT&CK knowledge are not collapsed into a universal maliciousness score.

Canonical GreyNoise IP enrichment is one Evidence v2 provider operation. It is separate from the Project Swarm session operator surface described later in this example.

#### 5. Intelligence Kernel v1.0 — IP reference

For IP results, the gateway can project deterministic **Intelligence Kernel v1.0** derived context from normalized evidence, explicit relationships, correlation and coverage.

Illustrative shape:

```json
{
  "intelligence": {
    "schemaVersion": "1.0",
    "type": "ip",
    "policy": {"type":"ip","version":"1.0"},
    "evidenceStrength": {"level":"moderate","reasons":[]},
    "sourceDiversity": {},
    "corroboration": [],
    "contradiction": {"level":"none","items":[]},
    "temporalRelevance": {"overall":"unknown"},
    "relationshipValue": [],
    "pivotCandidates": [],
    "threatContext": {},
    "huntRelevance": {},
    "coverageImpact": {"level":"none"},
    "analystPriority": {"level":"investigate","reasons":[]},
    "limitations": [],
    "ruleIds": []
  }
}
```

Kernel output is **derived context, not Evidence v2**. It creates no new provider observations and performs no network calls. Relationship candidates are explicit one-hop pivots only; free-text attributes are not mined for guessed infrastructure. Observation timestamps drive temporal relevance; `retrievedAt` is not reinterpreted as first/last seen.

There is no LLM, runtime learning or universal threat score in this path.

#### 6. Decision Support, graph, Guidance and report

A compatible IP Kernel projection can inform deterministic Decision Support disposition/confidence while preserving the legacy fallback if Kernel data is absent, malformed, wrong-version or wrong-type. Evidence Graph v1.0 remains built from explicit Evidence v2 facts/relationships and does not absorb Kernel-derived pivots as new evidence.

Guidance v1.0 can carry only a bounded Intelligence Kernel summary while existing evidence-fingerprint validation remains authoritative. The IP analyst report consumes the same Kernel-backed model for executive priority/strength, relationships/pivots, contradiction severity, temporal context, hunt relevance and coverage impact.

```json
{
  "decision": {
    "disposition": "investigate",
    "confidence": "medium",
    "reasons": ["<machine-readable reason>"],
    "huntPlan": []
  },
  "evidenceGraph": {"schemaVersion": "1.0", "nodes": [], "edges": []},
  "guidance": {"schemaVersion": "1.0", "disposition": "investigate", "confidence": "medium"}
}
```

Generated KQL or `hunt_now` guidance is a hunting hypothesis, not proof of compromise.

#### 7. Failure isolation

If the Kernel projection fails, usable enrichment is not discarded. Evidence v2, correlation and existing downstream fallbacks remain available, and `intelligence_projection_unavailable` is surfaced as a limitation. Missing timestamps remain unknown; failed/skipped sources remain unknown rather than benign.

#### 8. Browser-local case and investigation workspaces

The analyst UI can capture successful Evidence v2 results into a local case/investigation. Case snapshots, semantic diffs, exact typed cross-case sightings and `.para11ax` bundles live in browser-local IndexedDB. The gateway does not become a server-side case database.

User Scanner, native Shodan analyst-shell output and GreyNoise Project Swarm read output are operator surfaces and are **not** automatically persisted into Evidence v2 case evidence or Intelligence Kernel input. Compatible operator read results require explicit `investigation capture operator`; this records contextual operator material, not Evidence v2.

#### 9. Native Shodan operator path

The analyst can make an explicit bounded Shodan lookup without replacing the current Evidence v2 result:

```text
analyst@para11ax:~$ shodan host 203.0.113.10
```

Equivalent HTTP request:

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer <PARA11AX_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"command":"host","target":"203.0.113.10"}' \
  https://<gateway>/api/para11ax/shodan
```

Request path:

```text
analyst shell
  -> same-origin /api/para11ax/shodan
  -> bearer authentication
  -> fixed command/argument validation
  -> server-side SHODAN_API_KEY
  -> fixed https://api.shodan.io
  -> bounded normalization
  -> terminal output + creditImpact
  -> Evidence v2 / intelligence state unchanged
```

The same bounded command surface supports:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

`shodan search` is first-page only; returned match/service arrays are capped and large raw banners are removed. `shodan download`, arbitrary paging, caller-selected URLs and on-demand scan submission are disabled. Host/count/stats/info are classified as no-query-credit operations, domain consumes a query credit, and search may consume a query credit.

A Shodan-visible service remains exposure context rather than proof of compromise, exploitability, ownership or attribution.

#### 10. GreyNoise Project Swarm operator path

The Web analyst can search bounded GreyNoise session observations without converting the result into canonical evidence:

```text
analyst@para11ax:~$ swarm search --from 2026-09-05T00:00:00Z --to 2026-09-06T00:00:00Z --scope workspace --query "source.ip:203.0.113.10"
```

Equivalent request shape:

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer <PARA11AX_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"command":"search","scope":"workspace","startTime":"2026-09-05T00:00:00Z","endTime":"2026-09-06T00:00:00Z","query":"source.ip:203.0.113.10","page":1,"pageSize":25}' \
  https://<gateway>/api/para11ax/swarm
```

Request path:

```text
Web analyst shell
  -> same-origin /api/para11ax/swarm
  -> bearer authentication
  -> fixed command/scope/range/query/pivot validation
  -> server-side GREYNOISE_API_KEY
  -> fixed https://api.greynoise.io
  -> bounded session JSON or explicit one-session binary download
  -> read result = operator context; export = download only
  -> Evidence v2 / intelligence state unchanged
```

The live Swarm grammar is:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> [--scope workspace|demo] [--query <lucene>] [--include-counts]
swarm timeseries --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--field <allowlisted-field>] [--size <1..100>] [--interval <auto|1s|1m|1h|1d>]
swarm export <session-id> <pcap|raw-source|raw-destination>
```

`scope=workspace` relies on the applicable upstream Sensors entitlement; `scope=demo` relies on the applicable Swarm entitlement. Demo export is rejected locally. Query text, page/size values and pivot fields are bounded before egress. JSON read results and each single-session PCAP/raw export are capped at 4 MiB; bulk session export is not exposed.

After a successful `search`, `get`, `unique`, or `timeseries`, the analyst may explicitly preserve the contextual result:

```text
investigation capture operator
```

That capture does not create Evidence v2, maliciousness, ATT&CK mapping, corroboration or analyst disposition. `swarm export` never replaces the current operator result and is not automatically attached to the investigation. Full contract: `GREYNOISE-SWARM.md`.

#### 11. Optional STIX export

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer <PARA11AX_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"203.0.113.10","profile":"standard"}' \
  https://<gateway>/api/para11ax/stix
```

The gateway enriches first and maps only defensible Evidence v2 into a STIX 2.1 Bundle. Native Shodan shell output, GreyNoise Swarm operator output and Intelligence Kernel derived conclusions are not silently converted into new STIX evidence or attribution.

#### 12. Offline report path

A frozen Evidence v2 response can be compiled without provider/network calls:

```bash
para11ax report compile snapshot.json --out ./report --preset all
```

Canonical separation:

```text
canonical indicator
  -> profile admission
  -> Provider Value Scheduler v1.0
  -> Evidence v2
  -> typed correlation
  -> Intelligence Kernel v1.0 (IP reference)
  -> Decision / Evidence Graph / Guidance / report

explicit User Scanner command -> isolated active OSINT -> bounded operator context
explicit Shodan command -> fixed Shodan API -> bounded operator context
explicit GreyNoise Swarm read -> fixed GreyNoise API -> bounded operator context
explicit GreyNoise Swarm export -> fixed GreyNoise API -> bounded one-session browser download
```

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>