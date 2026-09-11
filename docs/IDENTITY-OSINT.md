<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Identity OSINT workflow

## Purpose

This workflow integrates the isolated User Scanner operator surface into the Authorised OSINT process without promoting scanner output directly into Evidence v2 or treating a registration/profile hit as proof of identity.

Use this workflow only for identifiers the operator owns, test fixtures, or investigations covered by explicit authorization and a legitimate defensive purpose.

## Canonical route

```text
scope / authority
  -> authoritative identity anchor
  -> passive public-source discovery
  -> User Scanner bounded username/email collection
  -> candidate social/profile/account leads
  -> exact-identifier pivots inside scope
  -> independent corroboration
  -> entity-resolution confidence
  -> PARA11AX Investigation Workspace operator context
  -> finding / exposure hypothesis
  -> infrastructure enrichment or XDR validation only when materially relevant
  -> remediation / report / re-test
```

## Trigger

Invoke User Scanner when the investigation has a legitimate identity question and at least one scoped username or email address. Typical defensive uses include self-exposure review, sanctioned impersonation/brand-risk review, account-surface discovery, stale-account discovery, incident scoping, and attribution support where the identifier is already lawfully in scope.

Do not invoke it merely because an investigation contains a person's name. Resolve an authoritative anchor first whenever possible.

## Collection policy

Start narrow. Prefer an exact username or email already tied to the scoped entity. Use module/category filters before broad cross-scan behavior when they can answer the question. Expand only when the previous result creates a specific, defensible hypothesis.

Useful result classes include:

- public profile URL or platform presence;
- public avatar, bio, display name, follower/count metadata, or other exposed profile fields;
- candidate aliases and username reuse;
- public account-registration indicators;
- public email/username relationships exposed by supported modules;
- operator-authorized breach/infostealer context when separately lawful and enabled.

## Semantic firewall

A User Scanner hit is an **investigative lead**, not proof of identity, ownership, activity, intent, compromise, or current control.

Classify every material result as one of:

- `OBSERVED` — the scanner returned a reproducible public signal;
- `CORROBORATED` — an independent authoritative or high-quality source confirms the same relationship;
- `INFERRED` — multiple signals support a relationship but direct confirmation is absent;
- `UNRESOLVED` — the signal is plausible but conflicting or insufficient;
- `REJECTED` — the signal was a false positive, same-name/handle collision, stale artifact, or otherwise disproven.

Only `CORROBORATED` observations should normally become confirmed OSINT findings. `OBSERVED` and `INFERRED` items remain pivots/hypotheses.

## Corroboration order

Prefer evidence in this order:

1. authoritative owned asset or official profile linkage;
2. target platform public profile/content;
3. primary-source website or repository controlled by the scoped entity;
4. second independent OSINT source;
5. generic search/index results.

Search repetition is not independent corroboration when multiple engines are indexing the same underlying page.

## PARA11AX integration

PARA11AX already exposes the bounded authenticated User Scanner route and CLI aliases:

```text
user-scanner username <target>
user-scanner email <target>
osint username <target> --module <module>
identity username <target> --category <category> --cross-scan
```

Scanner output remains an isolated operator result. Compatible results may be captured explicitly into Investigation Workspace context, but that capture is **not Evidence v2** and must not silently affect the Intelligence Kernel, Decision Support, or top-level threat conclusions.

Promote information onward only after corroboration and normalization. Preserve source/platform, queried identifier, retrieval time, module, returned URL/field, confidence, and the analyst's relationship judgment.

## Pivot policy

Allowed bounded pivots include exact aliases, public profile URLs, public domains linked by a corroborated profile, and infrastructure explicitly connected to the authorized entity.

A newly discovered sibling account, username, domain, person, company, IP, or service is a **candidate asset**, not automatic scan scope. Re-check authorization before target-directed interaction or broader enumeration.

## XDR bridge

Do not send identity-OSINT results into XDR merely because they exist. Bridge to first-party telemetry only when the result creates a falsifiable security hypothesis, for example:

- an authorized organization account is impersonated or exposed on a suspicious service;
- a known corporate identifier appears in infrastructure tied to a campaign;
- a scoped account relationship provides an entity key for sign-in, email, endpoint, or cloud telemetry;
- an incident needs to distinguish public exposure from evidence of tenant activity.

Before interpreting a zero-result XDR hunt, verify connector, table, schema, retention, freshness, and entity-key coverage.

## Evidence and privacy

Store the minimum normalized evidence required to reproduce the finding. Do not copy unnecessary personal data, credentials, raw restricted telemetry, or full third-party profiles into personal/public systems. Client-restricted results remain in the authorized client context.

For reports, preserve URLs/timestamps and redact unnecessary sensitive fields. If a finding materially affects a person, organization, or response action, require independent corroboration before escalation.

## Stop conditions

Stop expanding the identity graph when any of the following is true:

- the original defensive question is answered with sufficient corroboration;
- two consecutive pivot rounds add no material new relationship, contradiction, exposure, or action;
- rate limiting, blocking, scope ambiguity, or authorization uncertainty appears;
- further collection would add mostly personal data rather than security value.

## Default MAXX sequence

```text
Authorised OSINT Toolkit
  -> anchor-first entity resolution
  -> User Scanner identity/social discovery
  -> primary-source profile verification
  -> Exa/Parallel only for material recall gaps
  -> PARA11AX normalized operator context
  -> confidence + contradiction review
  -> XDR only for testable first-party hypotheses
  -> report/remediation
  -> same-probe re-test when applicable
```

The design goal is maximum useful recall with minimum attribution error: User Scanner increases discovery breadth; the Authorised OSINT Toolkit and PARA11AX semantic firewall prevent that breadth from becoming false certainty.