<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Identity OSINT workflow

## Purpose

This workflow integrates bounded defensive Google dorking, the isolated User Scanner operator surface, and the PARA11AX MCP control plane into the Authorised OSINT process without promoting search/scanner output directly into Evidence v2 or treating a registration/profile hit as proof of identity.

Use this workflow only for identifiers the operator owns, test fixtures, or investigations covered by explicit authorization and a legitimate defensive purpose.

## Canonical route

```text
scope / authority
  -> authoritative identity anchor
  -> exact-identifier Google dorks / passive public-source discovery
  -> User Scanner bounded username/email collection
       via Web/REST/CLI or MCP para11ax_user_scan
  -> candidate social/profile/account leads
  -> exact-identifier pivots inside scope
  -> independent corroboration
  -> entity-resolution confidence
  -> PARA11AX Investigation Workspace operator context
  -> finding / exposure hypothesis
  -> infrastructure enrichment or XDR validation only when materially relevant
  -> remediation / report / re-test
```

Full search-engine query policy and templates: [`GOOGLE-DORKING.md`](GOOGLE-DORKING.md). Remote tool contract: [`MCP.md`](MCP.md).

## Trigger

Invoke User Scanner when the investigation has a legitimate identity question and at least one scoped username or email address. Typical defensive uses include self-exposure review, sanctioned impersonation/brand-risk review, account-surface discovery, stale-account discovery, incident scoping, and attribution support where the identifier is already lawfully in scope.

Use defensive dorking when an exact identifier or owned/authorized domain can improve passive recall, historical discovery, published-document discovery, or accidental-indexing detection. Do not invoke either layer merely because an investigation contains a person's name. Resolve an authoritative anchor first whenever possible.

## Collection policy

Start narrow. Prefer an exact username or email already tied to the scoped entity. Run the smallest relevant Google dork family, then use User Scanner module/category filters before broad cross-scan behavior when they can answer the question. Expand only when the previous result creates a specific, defensible hypothesis.

Useful result classes include:

- public profile URL or platform presence;
- public avatar, bio, display name, follower/count metadata, or other exposed profile fields;
- candidate aliases and username reuse;
- public account-registration indicators;
- public email/username relationships exposed by supported modules;
- indexed historical documents, pages, repositories, error/config artifacts, or accidental exposure;
- operator-authorized breach/infostealer context when separately lawful and enabled.

## Preferred execution surfaces

The same bounded User Scanner handler is reachable through the browser/REST path and remotely through MCP. Prefer MCP when the investigation is already being orchestrated from ChatGPT or another authenticated MCP client because it removes the manual copy/paste boundary while preserving the same scanner validation and fixed worker destination.

MCP username example:

```json
{
  "name":"para11ax_user_scan",
  "arguments":{
    "scanType":"username",
    "target":"example_handle"
  }
}
```

MCP email example:

```json
{
  "name":"para11ax_user_scan",
  "arguments":{
    "scanType":"email",
    "target":"analyst@example.com"
  }
}
```

These are tool arguments, not evidence claims. MCP transport does not upgrade scanner output to a stronger authority class.

## Semantic firewall

A Google result or User Scanner hit is an **investigative lead**, not proof of identity, ownership, activity, intent, compromise, current control, or vulnerability.

Classify every material result as one of:

- `OBSERVED` — the search/scanner returned a reproducible public signal;
- `CORROBORATED` — an independent authoritative or high-quality source confirms the same relationship;
- `INFERRED` — multiple signals support a relationship but direct confirmation is absent;
- `UNRESOLVED` — the signal is plausible but conflicting or insufficient;
- `REJECTED` — the signal was a false positive, same-name/handle collision, stale artifact, or otherwise disproven.

Only `CORROBORATED` observations should normally become confirmed OSINT findings. `OBSERVED` and `INFERRED` items remain pivots/hypotheses. A zero-result Google query is `NOT_INDEXED_OR_NOT_RETURNED`, never proof of absence. A zero-result User Scanner pass is scanner-scoped non-observation, not proof that the identifier is unused.

## Corroboration order

Prefer evidence in this order:

1. authoritative owned asset or official profile linkage;
2. target platform public profile/content;
3. primary-source website or repository controlled by the scoped entity;
4. second independent OSINT source;
5. generic search/index results.

Search repetition is not independent corroboration when multiple engines are indexing the same underlying page. User Scanner modules that ultimately resolve the same underlying profile are also not independent merely because multiple module names returned it.

## PARA11AX integration

PARA11AX exposes the bounded authenticated User Scanner route and CLI aliases:

```text
user-scanner username <target>
user-scanner email <target>
osint username <target> --module <module>
identity username <target> --category <category> --cross-scan
```

The MCP equivalent is `para11ax_user_scan`. It delegates to the same bounded server-side User Scanner handler and therefore inherits the same worker URL, timeout, request/response and input validation. MCP cannot select the worker host, token, proxy, arbitrary module path, concurrency or arbitrary destination.

Google dork output and User Scanner output remain isolated operator context. Compatible results may be captured explicitly into Investigation Workspace context, but that capture is **not Evidence v2** and must not silently affect the Intelligence Kernel, Decision Support, or top-level threat conclusions.

Promote information onward only after corroboration and normalization. Preserve source/platform/search engine, rendered query when applicable, queried identifier, retrieval time, module, returned URL/field, confidence, and the analyst's relationship judgment.

## Pivot policy

Allowed bounded pivots include exact aliases, public profile URLs, public domains linked by a corroborated profile, and infrastructure explicitly connected to the authorized entity.

A newly discovered sibling account, username, domain, person, company, IP, cloud object, or service is a **candidate asset**, not automatic scan scope. Re-check authorization before target-directed interaction or broader enumeration.

MCP automation does not weaken this rule. A tool discovering a new identifier does not implicitly authorize the next scan.

## XDR bridge

Do not send identity-OSINT results into XDR merely because they exist. Bridge to first-party telemetry only when the result creates a falsifiable security hypothesis, for example:

- an authorized organization account is impersonated or exposed on a suspicious service;
- a known corporate identifier appears in infrastructure tied to a campaign;
- a scoped account relationship provides an entity key for sign-in, email, endpoint, or cloud telemetry;
- an incident needs to distinguish public exposure from evidence of tenant activity.

Before interpreting a zero-result XDR hunt, verify connector, table, schema, retention, freshness, and entity-key coverage.

## Evidence and privacy

Store the minimum normalized evidence required to reproduce the finding. Do not copy unnecessary personal data, credentials, raw restricted telemetry, full third-party profiles, or exposed secret values into personal/public systems. Client-restricted results remain in the authorized client context.

For reports, preserve URLs/timestamps/queries and redact unnecessary sensitive fields. If a finding materially affects a person, organization, or response action, require independent corroboration before escalation.

External MCP clients can persist conversation/tool state outside PARA11AX. Treat client-side retention and sharing as a separate data-handling boundary. Do not assume PARA11AX's stateless MCP server controls how the client stores returned identity data.

## Stop conditions

Stop expanding the identity graph when any of the following is true:

- the original defensive question is answered with sufficient corroboration;
- two consecutive dork/query/pivot rounds add no material new relationship, contradiction, exposure, or action;
- rate limiting, CAPTCHA behavior, blocking, scope ambiguity, or authorization uncertainty appears;
- further collection would add mostly personal data rather than security value.

## Default MAXX sequence

```text
Authorised OSINT Toolkit
  -> anchor-first entity resolution
  -> defensive Google dorking on exact scoped identifiers/domains
  -> MCP para11ax_user_scan when connected, otherwise existing User Scanner surface
  -> primary-source profile/document verification
  -> Exa/Parallel only for material recall gaps
  -> PARA11AX normalized operator context
  -> confidence + contradiction review
  -> XDR only for testable first-party hypotheses
  -> report/remediation
  -> same-query / same-probe re-test when applicable
```

The design goal is maximum useful recall with minimum attribution error: Google dorking adds indexed/historical/document exposure, User Scanner adds structured identity/social discovery, MCP removes the orchestration dead-end, and the Authorised OSINT Toolkit plus PARA11AX semantic firewall prevent that breadth from becoming false certainty.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
