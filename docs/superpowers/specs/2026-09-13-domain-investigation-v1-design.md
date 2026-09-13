<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
> **Document status:** Historical design record. Preserved for implementation history; current behavior is defined by [docs/ARCHITECTURE.md](https://github.com/ger1e/para11ax/blob/main/docs/ARCHITECTURE.md), [docs/DOMAIN-INVESTIGATION.md](https://github.com/ger1e/para11ax/blob/main/docs/DOMAIN-INVESTIGATION.md), and the current README.

# Domain Investigation v1 Design

## Purpose

Domain Investigation v1 recreates the useful defensive workflow described in Webamon's Hermes suspicious-domain investigation article as a PARA11AX-native, provenance-first workflow. It does not clone Hermes branding or implementation. PARA11AX remains authoritative for passive enrichment, correlation, evidence semantics, reporting, STIX output, MCP, and agent handoff. Active discovery or vulnerability scanning remains explicit, authorized, local/external work whose results are imported as contextual findings.

## Goals

- Start from one validated domain.
- Consume a canonical PARA11AX domain Evidence v2 enrichment as the passive-recon authority.
- Preserve Webamon as an existing registered Evidence v2 provider rather than creating a duplicate provider path.
- Import bounded surface-discovery and vulnerability-scanner findings without promoting them to Evidence v2.
- Extract and normalize domain, URL, IP, hash, ASN, certificate, and CVE pivots from passive evidence and imported findings.
- Produce deterministic block recommendations using explicit evidence rules, not an opaque 0-100 maliciousness score.
- Produce a deterministic analyst/SOC report, STIX 2.1 bundle, and next-agent handoff packet.
- Expose the workflow through pure core functions first, then shell/MCP adapters without adding arbitrary egress or server-side persistence.

## Non-goals

- No arbitrary active scanning from Vercel/MCP.
- No shell escape, arbitrary fetch destination, browser automation, or hidden server session.
- No LLM/adaptive maliciousness score.
- No automatic firewall/blocklist deployment.
- No automatic ServiceNow submission.
- No conversion of imported Nuclei/ZAP/discovery output into Evidence v2.
- No duplicate Webamon provider or caller-selected Webamon destination.

## Authority model

`passive` is authoritative Evidence v2 supplied by the existing domain enrichment path. `surface` and `vulnerabilities` are operator-context imports. Derived IOCs, block recommendations, report text, STIX objects, and handoff packets are projections. Every projection carries source/provenance references back to Evidence v2 fingerprints/providers or explicit imported-record identifiers.

## Workflow

```text
validated domain
  -> canonical domain Evidence v2 enrichment
  -> Webamon evidence inside the normal provider workflow
  -> bounded surface-discovery import (optional)
  -> bounded vulnerability import (optional)
  -> IOC extraction + normalization + dedupe
  -> deterministic block recommendation
  -> analyst report
  -> STIX 2.1
  -> next-agent handoff
```

The phase labels are `passive`, `webamon`, `surface`, `vulnerability`, `correlation`, and `output`. The workflow state reports phase readiness and gaps but does not pretend optional active phases were executed.

## Core object

`DomainInvestigationV1` is a frozen, deterministic projection containing:

- `schemaVersion: "domain-investigation-v1.0"`
- `target: { type: "domain", value }`
- `passive`: normalized summary of the supplied gateway enrichment, including request identity, queried time, represented providers, evidence fingerprints/references, relationships and Webamon presence
- `imports.surface[]`: bounded normalized findings
- `imports.vulnerabilities[]`: bounded normalized findings
- `iocs[]`: normalized unique pivots with type, value, provenance and evidence classes
- `recommendations[]`: deterministic `BLOCK | BLOCK_CANDIDATE | MONITOR | DO_NOT_BLOCK` dispositions with rule identifiers and reasons
- `phases[]`: phase state and gaps
- `limitations[]`
- `report`: structured deterministic SOC report projection
- `handoff`: bounded next-agent packet

No credentials, bearer tokens, raw HTML, packet captures, binary bodies, or runtime handles are stored.

## Input bounds

- Domain: canonical DNS hostname, maximum 253 characters.
- Passive enrichment: must be a gateway enrichment object for the same domain.
- Surface records: maximum 500 rows.
- Vulnerability records: maximum 500 rows.
- Maximum serialized imported context: 2 MiB per import class.
- Maximum field length: 4096 characters.
- Arrays inside imported records are bounded to 64 scalar values.
- Unknown or nested executable/object-heavy scanner structures are rejected or reduced to approved scalar fields; nothing is evaluated.

Surface import supports normalized records with fields such as `host`, `ip`, `url`, `port`, `protocol`, `service`, `technology`, `status`, `source`, and `reference`.

Vulnerability import supports normalized records with fields such as `host`, `url`, `templateId`, `cve`, `severity`, `title`, `matchedAt`, `source`, and `reference`.

## IOC normalization

Supported projected IOC types are `domain`, `url`, `ip`, `hash`, `asn`, `certificate`, and `cve`.

Passive relationships are mapped from canonical PARA11AX relationship targets. Imported records contribute only explicit scalar values. Values are normalized/deduplicated deterministically. Imported values retain `operator_context` authority and never gain Evidence v2 authority merely because they match a passive pivot.

## Recommendation rules

The workflow deliberately avoids a universal threat score.

- `BLOCK`: at least two independent direct malicious Evidence v2 sources for the exact IOC, or one authoritative campaign/malware association plus one independent current direct malicious source.
- `BLOCK_CANDIDATE`: one direct malicious Evidence v2 source plus independent corroborating threat context, or a vulnerability/surface finding attached to an IOC already carrying direct malicious evidence.
- `MONITOR`: suspicious/contextual relationships, Webamon observation, infrastructure proximity, scanner/noise/exposure context, or operator findings without direct malicious corroboration.
- `DO_NOT_BLOCK`: registration/routing/exposure/certificate/shared-infrastructure context alone, contradictory/insufficient evidence, or an IOC with no direct malicious source.

Every recommendation includes `ruleId`, `authority`, `directSources[]`, `contextSources[]`, `contradictions[]`, and human-readable `reasons[]`. Missing data must reduce confidence/actionability, never increase it.

## STIX 2.1

The workflow emits a deterministic STIX 2.1 bundle containing supported domain/IP/URL/hash/ASN indicators and CVE vulnerabilities from the projected IOC set. Objects include external references when safe HTTP(S) provenance exists. Imported-only IOCs receive no fabricated provider reference. The bundle is capped at 100 objects and uses stable UUIDv5 identities derived from canonical IOC identity.

## Report

The report contains target, phase state, passive provider/evidence summary, Webamon coverage, imported-surface summary, vulnerability summary, IOC table, recommendation summary, contradictions, limitations, and recommended analyst actions. It must explicitly state that imported findings are operator context and that no active scan was executed by PARA11AX.

## Handoff

The next-agent packet is deterministic and contains:

- workflow schema/version and target
- completed/ready phases
- evidence fingerprints/provider names
- operator-context record identifiers
- top unresolved pivots
- block recommendations requiring human action
- limitations/gaps
- bounded next actions
- context budget summary

It must be sufficient for another agent to continue without rereading raw scanner output. It never contains credentials or raw oversized evidence.

## Shell / MCP

Shell commands use an explicit artifact model rather than hidden server persistence:

```text
domain-investigation build <gateway-enrichment-json>
domain-investigation surface-import <artifact-json> <surface-json>
domain-investigation vulnerability-import <artifact-json> <vulnerability-json>
domain-investigation show <artifact-json>
domain-investigation report <artifact-json>
domain-investigation stix <artifact-json>
domain-investigation handoff <artifact-json>
```

CLI may additionally accept exact `--file`/`--stdin` transports where the existing shell transport model supports them. MCP exposes one grouped stateless tool that takes an explicit `action` and explicit artifact/input payload. The server stores no Domain Investigation state between calls.

## Security invariants

- Core implementation has no network calls, child process execution, secret access, dynamic evaluation, or filesystem write.
- Provider execution remains in existing PARA11AX enrichment paths and fixed egress controls.
- Webamon remains the existing registered provider and fixed `pro.webamon.com` adapter.
- Imported scanner/discovery data is untrusted input and is bounded/normalized before use.
- Recommendations are advisory projections only.
- Active-scanning instructions are not executed by the server; users remain responsible for authorization and scope.

## Tests

Tests cover domain/enrichment identity mismatch, bounds, hostile nested import data, IOC normalization/deduplication, Webamon detection, authority separation, recommendation rules, contradiction downgrade, report invariants, STIX validity/determinism/object cap, handoff continuity/context bounds, shell registration, MCP stateless contract, and documentation drift.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
