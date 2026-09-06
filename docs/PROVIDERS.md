<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Providers

The executable provider registry is the source of truth for the canonical Evidence v2 enrichment fabric. The active registry contains **38 providers**. `release-manifest.json` records active adapter/parser versions, and `/api/para11ax/meta` exposes static capabilities without credential values or secret configuration state.

#### Registry contract

Every active Evidence v2 provider declares and is validated for supported indicator/observation types, tier/cost class, timeout/cache policy, response ceiling, exact fixed host(s), allowed methods/protocols, parser version, source URL, credential posture and source semantics. Scheduler-aware providers can additionally expose declarative execution-value metadata; that metadata does not change fixed hosts, credentials or provider admission.

A canonical workflow cannot route to an unregistered provider or a provider that does not support that indicator type. The nine Evidence v2 workflows are `ip`, `domain`, `url`, `hash`, `cve`, `attack`, `asn`, `cidr`, and `certificate`.

#### Current provider fabric

**Identity / routing / exposure:** IPinfo · RDAP · RIPEstat · Shodan · Censys · Modat Magnify · Cloudflare Radar · Cloudflare DNS · Tor Exit · Spamhaus DROP / ASN-DROP.

**Threat / IOC:** DShield · Feodo Tracker · ThreatMiner · CIRCL MISP OSINT · Botvrij MISP OSINT · GreyNoise · AbuseIPDB · VirusTotal · OTX · ThreatFox · urlscan.io · Webamon · Pulsedive · OpenPhish · URLhaus · TweetFeed.

**File / malware:** CIRCL Hashlookup · MalwareBazaar · Malpedia · Hybrid Analysis.

**Vulnerability / ATT&CK:** CISA KEV · FIRST EPSS · CIRCL Vulnerability-Lookup · NVD · OSV · MITRE ATT&CK TAXII.

**Ransomware:** RansomLook · Ransomware.live API-PRO.

#### Provider Value Scheduler v1.0

Provider selection/admission and execution order are different concerns. Fixed workflow/profile rules decide which providers are admitted. **Provider Value Scheduler v1.0** deterministically orders those admitted adapters.

Scheduler descriptors are static, type-aware metadata. The policy comparator uses authority, semantic uniqueness, direct threat value, pivot value, latency class and cost class, then existing tier/workflow order for deterministic fallback. It does not learn from prior requests or suppress sources based on evidence already returned.

Current **24-provider IP workflow** keeps the same membership and the existing **48-call ceiling** (maximum two attempts/provider), maximum concurrency 4 and 20-second request deadline.

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
- EPSS: exploitation probability.
- NVD/CIRCL/OSV: vulnerability metadata.
- MITRE ATT&CK TAXII: knowledge/mapping context.
- reputation/malware services: provider-specific threat observations.
- RansomLook/ransomware.live: victim-claim/reporting context rather than compromise proof.

These classes are not interchangeable. A service exposure, Tor exit, scanner hit, registration record, certificate record, community IOC report, ransomware claim or ATT&CK technique is not automatically a malware-reputation vote.

#### Provider capability coverage and Intelligence Kernel

For the IP reference path, approved provider capability/source-role metadata can be projected into request coverage so **Intelligence Kernel v1.0** can distinguish redundant capability loss from materially unique capability loss. Failure/skip state remains coverage only; it is not converted into negative threat evidence.

The Kernel consumes normalized evidence/coverage after provider execution. It cannot call a provider, change scheduler ordering, expand the provider registry or change an adapter's semantic class. Evidence v2 remains authoritative.

#### Shodan: two distinct surfaces

Shodan appears in PARA11AX in two deliberately separate ways.

1. **Evidence v2 provider adapter** — Shodan is one of the 38 fixed providers used where the canonical workflow/profile allows it. Its observations enter the normal provider parser/evidence/correlation path with exposure semantics and can support deterministic derived context without becoming a reputation vote by themselves.
2. **Native analyst-shell utility** — `POST /api/para11ax/shodan` implements explicit bounded operator lookups for `shodan host`, `search`, `count`, `stats`, `domain`, and `info`.

The shell utility does **not** add a 39th provider, does not change the provider registry/scheduler, and does not automatically promote its output into Evidence v2 or Intelligence Kernel input.

Both surfaces use server-side `SHODAN_API_KEY`; the browser never receives that key. The shell route contacts only `https://api.shodan.io`, rejects arbitrary destinations/options, caps returned data, removes large raw service/banner bodies, keeps search first-page only, and disables `shodan download`.

Credit handling is explicit on the shell route: host/count/stats/info are no-query-credit operations; domain consumes a query credit; search may consume a query credit. See `SHODAN-SHELL.md`.

#### GreyNoise: canonical provider plus Project Swarm operator surface

GreyNoise also appears in two distinct ways without increasing the 38-provider count.

1. **Evidence v2 provider adapter** — canonical IP enrichment uses authenticated GreyNoise v3 IP Lookup at the fixed GreyNoise API origin. The default workspace-label request is `greynoise,community,personal`, optionally overridden by `GREYNOISE_WORKSPACE_LABELS`. Returned tags, CVEs and scanned ports can become normalized provider observations; PARA11AX only asserts dataset/workspace provenance when the upstream response explicitly supplies matching label information.
2. **GreyNoise Project Swarm operator utility** — `POST /api/para11ax/swarm` implements bounded Web-only session `search`, `get`, allowlisted `unique`, allowlisted `timeseries`, and explicit single-session `export` operations.

The Swarm utility is not a 39th provider, is not scheduled by Provider Value Scheduler v1.0, and does not automatically promote session/pivot/export output into Evidence v2 or Intelligence Kernel input. Successful `search`, `get`, `unique`, and `timeseries` results can be explicitly captured as Investigation Workspace operator context; PCAP/raw export remains an explicit browser download outside automatic capture.

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

A provider can be:

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