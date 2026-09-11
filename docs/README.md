<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX documentation

This directory is the canonical documentation set for PARA11AX. Start with the control plane that matches how you intend to operate the platform, then follow the authority/security documents before interpreting results.

## Fast path

For remote/agentic operation:

```text
MCP.md
  -> API.md
  -> ARCHITECTURE.md
  -> relevant workflow document
  -> SECURITY-CONTROLS.md / THREAT-MODEL.md
  -> OPERATIONS.md / QA-REPORT.md
```

For browser/terminal operation:

```text
SHELL.md
  -> relevant operator/workflow document
  -> EVIDENCE-SCHEMA.md
  -> SECURITY-CONTROLS.md
```

For defensive identity OSINT:

```text
IDENTITY-OSINT.md
  -> GOOGLE-DORKING.md
  -> MCP.md (para11ax_user_scan) or existing User Scanner surface
  -> source corroboration
  -> Investigation Workspace operator context
```

## Control planes and interfaces

| Document | Purpose |
| --- | --- |
| [`MCP.md`](MCP.md) | Authenticated stateless remote control plane, 13 grouped tools, transport rules, state model and remote safety boundary. |
| [`API.md`](API.md) | REST route inventory plus `/mcp` protocol surface and request/response contracts. |
| [`SHELL.md`](SHELL.md) | Canonical registered analyst-shell grammar, pipelines and surface-specific command constraints. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Shared domain logic, trust boundaries, Evidence v2 path, MCP delegation model and state separation. |

## Intelligence and evidence

| Document | Purpose |
| --- | --- |
| [`EVIDENCE-SCHEMA.md`](EVIDENCE-SCHEMA.md) | Evidence v2 authority, semantic classes, provenance, graph/guidance boundaries and absence/failure semantics. |
| [`PROVIDERS.md`](PROVIDERS.md) | Canonical 38-source provider fabric, workflow admission and scheduler metadata. |
| [`END-TO-END-EXAMPLE.md`](END-TO-END-EXAMPLE.md) | Worked enrichment/analysis example through the deterministic evidence path. |
| [`ANALYST-MISSION-PACK.md`](ANALYST-MISSION-PACK.md) | Client relevance → hunt → KQL validation → result analysis → ServiceNow-ready projection. |

## OSINT and operator workflows

| Document | Purpose |
| --- | --- |
| [`IDENTITY-OSINT.md`](IDENTITY-OSINT.md) | Authorised username/email workflow: anchor → dorks → User Scanner → corroboration → operator context. |
| [`GOOGLE-DORKING.md`](GOOGLE-DORKING.md) | Defensive Google operator taxonomy and bounded dork families for indexed exposure discovery. |
| [`SHODAN-SHELL.md`](SHODAN-SHELL.md) | Bounded Shodan operator commands, credit semantics and fixed-upstream boundary. |
| [`GREYNOISE-SWARM.md`](GREYNOISE-SWARM.md) | Project Swarm search/get/unique/timeseries/diff/export semantics and entitlement boundaries. |

## Assurance, security and release

| Document | Purpose |
| --- | --- |
| [`SECURITY-CONTROLS.md`](SECURITY-CONTROLS.md) | Control-to-risk mapping including MCP, provider, User Scanner, Shodan, Swarm and state boundaries. |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Assets, adversaries, failure modes, residual risk and out-of-scope capabilities. |
| [`OPERATIONS.md`](OPERATIONS.md) | Proof-state model, current production baseline, deployment acceptance and MCP verification sequence. |
| [`QA-REPORT.md`](QA-REPORT.md) | Verification evidence and explicit limits of what a QA pass proves. |
| [`PUBLIC-RELEASE-CHECKLIST.md`](PUBLIC-RELEASE-CHECKLIST.md) | Public-release and publication guardrails. |
| [`../SECURITY.md`](../SECURITY.md) | Vulnerability reporting and repository-wide security posture. |

## Branding and presentation

| Document | Purpose |
| --- | --- |
| [`BRAND.md`](BRAND.md) | PARA11AX visual/interaction identity and presentation constraints. |

## Core authority rules

The interface used to obtain a result does not change its evidentiary authority:

```text
Evidence v2 provider observation = evidence
Intelligence Kernel / Decision / Guidance = deterministic derived context
User Scanner / Shodan / GreyNoise Swarm = operator context unless independently promoted by an Evidence v2 workflow
Google dork/search hit = investigative lead until source/entity corroboration
Imported XDR/KQL result = external result-analysis input
Disposition = explicit analyst judgment
MCP = transport/control plane, not an authority class
```

Absence is not benignness. Infrastructure proximity is not attribution. A matching username/email/profile is not same-person proof. A tool/provider failure is not negative evidence. MCP does not bypass those rules.

## Current remote entry point

```text
POST https://para11ax.vercel.app/mcp
MCP-Protocol-Version: 2026-07-28
```

See [`MCP.md`](MCP.md) before configuring an external MCP client. A live MCP route proves transport availability only; client authentication and each credentialed provider/worker/entitlement remain separate proof states.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
