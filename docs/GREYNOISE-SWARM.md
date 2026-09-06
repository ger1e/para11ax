<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# GreyNoise Project Swarm

PARA11AX exposes GreyNoise Project Swarm sessions as a bounded Web-terminal specialist surface. It is separate from ordinary IOC enrichment: routine `gn` / GreyNoise provider execution cannot enumerate sessions or retrieve packet data.

The browser never receives `GREYNOISE_API_KEY`. Every Swarm operation crosses the authenticated same-origin PARA11AX gateway and the server contacts only `https://api.greynoise.io` with redirects disabled.

## Commands

Search sessions within an explicit time range:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
```

Example:

```text
swarm search --from 2026-09-05T00:00:00Z --to 2026-09-06T00:00:00Z --scope workspace --query "classification:malicious" --page-size 50
```

Read one session:

```text
swarm get <session-id> [--scope workspace|demo]
```

Export one workspace session:

```text
swarm export <session-id> <pcap|raw-source|raw-destination>
```

`raw-source` maps to GreyNoise `rawSource`; `raw-destination` maps to `rawDestination`.

## Bounds

- The surface is **WEB ONLY** and requires the normal volatile PARA11AX bearer.
- Search requires both `--from` and `--to`; PARA11AX rejects invalid timestamps and ranges where `from >= to` before egress.
- Search page size is capped at 100 and page number at 10,000.
- Lucene query text is capped at 2,048 printable characters.
- Session IDs are restricted to a bounded safe identifier grammar and are URL-encoded before use.
- JSON session responses are capped at 4 MiB and normalized through a bounded structural sanitizer.
- Export is one session per command and capped at 4 MiB.
- Bulk `/v3/sessions/export` is intentionally not exposed.
- `scope=demo` is read-only in PARA11AX. Export is rejected locally before GreyNoise egress.
- Upstream redirects are refused and responses are `no-store`.

## Trust boundary

```text
Browser terminal
  -> POST /api/para11ax/swarm
  -> PARA11AX bearer validation
  -> strict command/request validation
  -> fixed https://api.greynoise.io destination
  -> server-side GREYNOISE_API_KEY
  -> bounded JSON record or explicit single-session binary download
```

Swarm output is operator context. It is not automatically promoted into Evidence v2, correlation, maliciousness, ATT&CK mappings, or investigation judgment. Packet/payload export is an explicit analyst action.

## Upstream mapping

PARA11AX maps the commands to the GreyNoise Session API as follows:

```text
swarm search  -> GET /v3/sessions
swarm get     -> GET /v3/sessions/{session_id}
swarm export  -> GET /v3/sessions/{session_id}/export
```

Search sends GreyNoise's documented `scope`, `start_time`, `end_time`, optional `query`, `page`, and `page_size` parameters and fixes sorting to newest `lastPacket` first.

Export supports only GreyNoise's documented single-session types: `pcap`, `rawSource`, and `rawDestination`.

Vendor references:

- https://docs.greynoise.io/reference/getsessions
- https://docs.greynoise.io/reference/getsessionbyid
- https://docs.greynoise.io/reference/exportsession

## Failure semantics

PARA11AX keeps operational failure distinct from intelligence content. Authentication/entitlement failure, rate limiting, missing sessions, upstream errors, timeouts, oversized responses, malformed JSON, and transport errors return explicit normalized errors. None are converted into negative threat evidence.

GreyNoise credentials are never copied into response bodies, filenames, terminal history, operator records, or references.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
