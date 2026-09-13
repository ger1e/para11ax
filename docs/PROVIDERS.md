<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Providers

The executable provider registry is the source of truth for the canonical Evidence v2 and Intelligence Fabric provider surface. The active registry contains **45 provider capabilities** spanning **41 upstream services**. The difference is intentional: VirusTotal, Censys and urlscan.io each expose bounded sibling capabilities under a shared provider family rather than pretending each execution mode is a new upstream source. VulnCheck and deps.dev add two explicit graph-only upstream services and do not widen the 39-source baseline enrichment fabric. `release-manifest.json` records active adapter/parser versions, and `/api/para11ax/meta` exposes static capabilities without credential values or secret configuration state.

#### Registry contract

Every active provider declares and is validated for supported indicator/observation types, tier/cost class, timeout/cache policy, response ceiling, exact fixed host(s), allowed methods/protocols, parser version, source URL, credential posture and source semantics. Intelligence Fabric capabilities can additionally declare execution mode, fanout eligibility, sensitivity, authorization, retention, bounded paging/relationship limits and provider family. Scheduler-aware providers can expose declarative execution-value metadata; that metadata does not change fixed hosts, credentials or provider admission.

A canonical workflow cannot route to an unregistered provider or a provider that does not support that indicator type. The nine Evidence v2 enrichment workflows remain `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, and `certificate`. Non-enrichment Intelligence Fabric capabilities, such as `virustotal-graph`, `urlscan-graph`, `censys-search`, `censys-history`, `vulncheck` and `deps-dev`, are selectable only through their declared mode and do not enter ordinary enrichment fanout.

#### Current provider fabric

**Identity / routing / exposure:** IPinfo · RDAP · RIPEstat · Shodan · Censys point enrichment · Censys bounded search · Censys certificate history · Modat Magnify · Cloudflare Radar · Cloudflare DNS · Tor Exit · Spamhaus DROP / ASN-DROP.

**Threat / IOC:** DShield · Feodo Tracker · ThreatMiner · CIRCL MISP OSINT · Botvrij MISP OSINT · GreyNoise · AbuseIPDB · VirusTotal point enrichment · VirusTotal bounded graph · OTX · ThreatFox · urlscan.io point enrichment · urlscan.io bounded graph · Webamon · Pulsedive · OpenPhish · URLhaus · TweetFeed.

**File / malware:** CIRCL Hashlookup · MalwareBazaar · Malpedia · Hybrid Analysis.

**Vulnerability / ATT&CK:** CISA KEV · CISA ADP SSVC · FIRST EPSS · CIRCL Vulnerability-Lookup · NVD · OSV · VulnCheck exploit intelligence · MITRE ATT&CK TAXII.

**Supply chain:** deps.dev package/dependency graph intelligence.

**Ransomware:** RansomLook · Ransomware.live API-PRO.

#### Provider Value Scheduler v1.0

Provider selection/admission and execution order are different concerns. Fixed workflow/profile rules decide which providers are admitted. **Provider Value Scheduler v1.0** deterministically orders those admitted adapters.

Scheduler descriptors are static, type-aware metadata. The policy comparator uses authority, semantic uniqueness, direct threat value, pivot value, latency class and cost class, then existing tier/workflow order for deterministic fallback. It does not learn from prior requests or suppress sources based on evidence already returned.

Current **24-provider IP workflow** keeps the same membership and the existing **48-call ceiling** (maximum two attempts/provider), maximum concurrency 4 and 20-second request deadline. The non-enrichment sibling capabilities are not part of that baseline workflow because their declared mode is `graph` or `search` and `fanoutEligible` is false.

IP execution order v1:

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

Scheduling invariants:

- every admitted provider remains scheduled;
- no evidence-dependent omission;
- missing/malformed scheduler metadata falls back deterministically;
- scheduling cannot broaden `safeFetch` egress;
- public capability metadata can describe scheduler policy/descriptors but never credentials, arbitrary runtime rank inputs or threat conclusions;
- scheduler ordering is not a maliciousness score.

#### Source semantics

Provider observations preserve their own meaning. Examples:

- RDAP: registration context.
- RIPEstat: routing context.
- Shodan/Censys/Modat: service/infrastructure exposure context.
- DShield: scanner activity.
- GreyNoise: provider-specific internet-noise/scanner/threat context from the fixed v3 IP lookup; dataset provenance is claimed only when the upstream response explicitly supplies applicable workspace labels.
- Spamhaus DROP/ASN-DROP: netblock/ASN listing context.
- Tor exit: Tor infrastructure context.
- CISA KEV: known exploited status.
- CISA ADP SSVC: CISA Stakeholder-Specific Vulnerability Categorization context from the CVE record's CISA ADP container; upstream `Exploitation`, `Automatable`, and `Technical Impact` decisions remain separate axes and are not collapsed into a score.
- EPSS: exploitation probability.
- NVD/CIRCL/OSV: vulnerability metadata.
- VulnCheck: exploit-presence and exploit-maturity context from its bounded CVE exploit index; presence does not replace KEV/EPSS/CVSS axes.
- deps.dev: package identity, direct/transitive dependency and supply-chain relationship context; dependency presence is not a maliciousness verdict.
- MITRE ATT&CK TAXII: knowledge/mapping context.
- VirusTotal point enrichment: provider-specific reputation, malware association and certificate context.
- VirusTotal graph: explicit bounded relationships such as resolutions, communicating files, historical certificates and contacted infrastructure; relationship presence is context, not a new maliciousness vote.
- Censys search/history: explicit bounded internet-exposure, certificate and historical certificate-presentation context; search/history presence is not reputation evidence.
- urlscan.io graph: bounded web-scan relationship context from one search page plus one selected result, including redirect, request-host, contacted-IP, URL, certificate, body-hash, download and technology pivots.
- RansomLook/ransomware.live: victim-claim/reporting context rather than compromise proof.

These classes are not interchangeable. A service exposure, Tor exit, scanner hit, registration record, certificate record, community IOC report, ransomware claim or ATT&CK technique is not automatically a malware-reputation vote.

#### Provider capability coverage and Intelligence Kernel

For the IP reference path, approved provider capability/source-role metadata can be projected into request coverage so **Intelligence Kernel v1.0** can distinguish redundant capability loss from materially unique capability loss. Failure/skip state remains coverage only; it is not converted into negative threat evidence.

The Kernel consumes normalized evidence/coverage after provider execution. It cannot call a provider, change scheduler ordering, expand the provider registry or change an adapter's semantic class. Evidence v2 remains authoritative.

#### VirusTotal: point enrichment plus bounded graph capability

VirusTotal deliberately occupies two registered capabilities under one upstream provider family.

1. **Point enrichment** — `virustotal` remains the normal `enrich` capability for IP, domain, URL, hash and certificate lookups. It remains eligible for the existing fixed enrichment workflows.
2. **Graph expansion** — `virustotal-graph` is a separate `graph` capability for IP, domain and hash roots. It is non-fanout, uses at most one page per relationship class, caps each request at 20 records and caps normalized relationships at 60.

The graph adapter follows only hard-coded documented relationship classes. Domain/IP roots can request `resolutions`, `communicating_files` and `historical_ssl_certificates`; file-hash roots can request `contacted_domains`, `contacted_ips` and `contacted_urls`. Pagination links are not followed. Returned objects must match the expected relationship type and pass canonical observable validation before they become relationship targets. HTTP 404 is neutral absence; entitlement or authorization failures such as 403 remain explicit provider failures and are never converted into negative evidence.

#### Censys: point enrichment plus bounded search/history capabilities

Censys occupies three registered capabilities under the `censys` provider family.

1. **Point enrichment** — `censys` remains the normal enrichment path for IP and certificate lookups.
2. **Search** — `censys-search` is a non-fanout `search` capability for IP, domain and certificate roots. PARA11AX generates the exact CenQL from the canonical observable, submits one fixed POST page with explicit field allowlists and never accepts caller-supplied raw CenQL.
3. **Certificate history** — `censys-history` is a non-fanout `graph` capability for certificate roots. It requests one bounded historical host-observation page and requires the non-secret configured `CENSYS_ORG_ID` scope before egress.

Neither deep capability follows pagination tokens. Search is capped at 25 hits / 75 normalized relationships and history at 50 rows / 50 relationships. HTTP 404 remains neutral absence; entitlement failures remain provider failures; malformed successful schemas fail closed.

#### urlscan.io: point enrichment plus bounded result graph

urlscan.io occupies two registered capabilities under the `urlscan` provider family.

1. **Point enrichment** — `urlscan` preserves the existing search-based web observation path for IP, domain and URL roots.
2. **Deep result graph** — `urlscan-graph` is a non-fanout `graph` capability. It fetches one search page capped at five candidates, selects one valid result UUID, then fetches exactly one `/api/v1/result/{uuid}/` document. Search pagination is never followed.

Deep-result relationships are capped at 64 and every target passes explicit canonical observable validation. Markup-bearing values are rejected rather than stripped into fabricated pivots. Missing/deleted results (404/410) are neutral absence; other upstream failures remain explicit failures.

#### Shodan: two distinct surfaces

Shodan appears in PARA11AX in two deliberately separate ways.

1. **Evidence v2 provider adapter** — Shodan is one registered enrichment capability used where the canonical workflow/profile allows it. Its observations enter the normal provider parser/evidence/correlation path with exposure semantics and can support deterministic derived context without becoming a reputation vote by themselves.
2. **Native analyst-shell utility** — `POST /api/para11ax/shodan` implements explicit bounded operator lookups for `shodan host`, `search`, `count`, `stats`, `domain`, and `info`.

The shell utility does not add another provider capability or upstream service, does not change the provider registry/scheduler, and does not automatically promote its output into Evidence v2 or Intelligence Kernel input.

Both surfaces use server-side `SHODAN_API_KEY`; the browser never receives that key. The shell route contacts only `https://api.shodan.io`, rejects arbitrary destinations/options, caps returned data, removes large raw service/banner bodies, keeps search first-page only, and disables `shodan download`.

Credit handling is explicit on the shell route: host/count/stats/info are no-query-credit operations; domain consumes a query credit; search may consume a query credit. See `SHODAN-SHELL.md`.

#### GreyNoise: canonical provider plus Project Swarm operator surface

GreyNoise also appears in two distinct ways without increasing the registered provider-capability or upstream-service counts.

1. **Evidence v2 provider adapter** — canonical IP enrichment uses authenticated GreyNoise v3 IP Lookup at the fixed GreyNoise API origin. The default workspace-label request is `greynoise,community,personal`, optionally overridden by `GREYNOISE_WORKSPACE_LABELS`. Returned tags, CVEs and scanned ports can become normalized provider observations; PARA11AX only asserts dataset/workspace provenance when the upstream response explicitly supplies matching label information.
2. **GreyNoise Project Swarm operator utility** — `POST /api/para11ax/swarm` implements bounded Web-only session `search`, `get`, allowlisted `unique`, allowlisted `timeseries`, and explicit single-session `export` operations.

The Swarm utility is not registered as another provider capability, is not scheduled by Provider Value Scheduler v1.0, and does not automatically promote session/pivot/export output into Evidence v2 or Intelligence Kernel input. Successful `search`, `get`, `unique`, and `timeseries` results can be explicitly captured as Investigation Workspace operator context; PCAP/raw export remains an explicit browser download outside automatic capture.

Both GreyNoise surfaces use server-side `GREYNOISE_API_KEY`; the browser never receives it. Swarm egress is fixed to `https://api.greynoise.io`, redirects are refused, search/pivot ranges and fields are bounded, JSON and individual binary export are capped at 4 MiB, bulk session export is omitted, and `scope=demo` export is rejected before egress.

`scope=workspace` session reads depend on the applicable Sensors entitlement; `scope=demo` reads depend on the applicable Swarm entitlement. Repository implementation/configuration cannot prove either account entitlement. See `GREYNOISE-SWARM.md`.

#### Certificate semantics

Certificate lookup is explicit and contextual. The canonical classifier requires `cert-sha256:<64-hex>` so a certificate fingerprint cannot silently steal a bare SHA-256 from the file-hash workflow. Certificate subject/issuer names, reuse, infrastructure proximity, or mere presence are investigative context rather than reputation or attribution proof.

#### Public feed hardening

Public feed parsers reject malformed content rather than manufacture `not_listed` results. MISP feed hash-cache hits are verified against exact event attributes; deleted attributes are excluded; composite attribute types compare only the corresponding component; event fetches are bounded.

ATT&CK TAXII uses fixed MITRE collection IDs and server-side type filtering. Relationship expansion remains omitted where collection-wide retrieval would violate boundedness.

#### Network indicator support

ASN/CIDR support is deliberately narrow and fixed-source: RDAP autnum/network registration, RIPEstat AS/Prefix Overview, and Spamhaus ASN-DROP / IPv4/IPv6 DROP. No active scanning is performed by the Evidence v2 provider fabric.

The Shodan analyst-shell surface performs only documented Shodan API lookups; it does not expose on-demand scan submission or arbitrary scanning. GreyNoise Swarm exposes only stored/session observation search/detail/pivots and explicit bounded export; it is not an arbitrary active scanner.

#### State model

A provider capability can be:

- **Implemented** — adapter exists and repository tests pass.
- **Configured** — required runtime secret is present; inspect authenticated health/status/probes.
- **Production-verified** — an authorized smoke operation succeeded against the exact deployed source SHA.
- **Unavailable/gap** — omitted, unconfigured, or failed its source/boundedness gate.

Implemented does not imply configured, and configured does not imply production-verified. For GreyNoise Swarm, account entitlement is an additional upstream state and must not be inferred from the presence of `GREYNOISE_API_KEY`.

#### Intentionally omitted

- SecurityTrails stale/paid assumptions.
- Deprecated SSLBL C2 path.
- TLS/JA3 indicator class without a suitable fixed bounded source.
- Unbounded ATT&CK relationship download.
- Ransomware-wide unbounded enumeration in per-indicator enrichment.
- Modat bulk export/broad history in normal enrichment.
- Shodan arbitrary paging, bulk `download`, caller-selected URLs, and on-demand scan submission through the analyst shell.
- GreyNoise arbitrary session fields, caller-selected destinations/methods, demo export, bulk `/v3/sessions/export`, and automatic packet/payload promotion into Evidence v2.
- LLM/adaptive provider scheduling or evidence-dependent source suppression.

Run `node scripts/generate-release-manifest.mjs --check` to detect registry/parser-version drift. Documentation-contract tests separately detect drift in externally documented workflow/provider/scheduler/operator facts.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
