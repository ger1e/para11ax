<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Defensive Google dorking OSINT playbook

## Purpose

This playbook integrates search-engine discovery into the Authorised OSINT workflow for self-assessment and explicitly authorised defensive investigations. It is a **query-construction and evidence-triage layer**, not an exploitation capability.

Google dorks are search queries that combine ordinary terms with search operators to locate indexed material. OffSec's Google Hacking Database (GHDB) is a long-running categorized catalog of such queries; OWASP also treats search-engine reconnaissance as a legitimate information-leakage testing technique. The useful abstraction is the exposure class, not blindly replaying thousands of historical strings.

## Canonical route

```text
scope / authority
  -> authoritative target anchor
  -> baseline site/index discovery
  -> operator/dork family selected by hypothesis
  -> Google query
  -> candidate URL/document/account/exposure
  -> direct source fetch when safe and public
  -> corroboration / ownership check
  -> OBSERVED / CORROBORATED / INFERRED / UNRESOLVED / REJECTED
  -> PARA11AX Investigation Workspace operator context
  -> remediation / report / same-query re-test
```

For identity investigations, insert this layer before or alongside User Scanner:

```text
authoritative identity anchor
  -> exact email/username dorks
  -> User Scanner recall expansion
  -> target-platform / owned-source corroboration
  -> relationship confidence
```

## Search-operator reliability

### Tier A — currently documented by Google

Use these as the stable baseline:

| Operator | Defensive use |
| --- | --- |
| `"exact phrase"` | Exact identifiers, emails, handles, product strings, error text |
| `site:` | Restrict to an owned/authorised domain, host, URL prefix, or known platform |
| `-term` / `-site:` | Remove common collisions and noisy sources |
| `filetype:` | Find indexed document/file classes |
| `before:` | Historical cut-off |
| `after:` | Recent-change cut-off |
| `imagesize:` | Google Images: exact image dimensions |
| `src:` | Google Images: pages referencing a specific image URL |

Google explicitly warns that `site:` and other operators are constrained by indexing/retrieval limits. A missing result is **not proof of absence**.

### Tier B — opportunistic / execution-verified

These remain useful in practice but should be treated as best-effort syntax rather than a guaranteed API contract:

- `intitle:`
- `inurl:`
- `intext:`
- `inanchor:`
- `OR`
- `*` wildcard inside phrase-oriented searches

If a Tier-B query produces unexpected results, simplify it into Tier-A components before drawing conclusions.

### Deprecated / do not rely on

- `cache:` — no longer works in Google Search; never include it in current runbooks or evidence expectations.

## Query-construction rules

1. **Anchor first.** Start with a verified owned/authorised domain, exact username, exact email, repository, company name, or known public profile.
2. **One hypothesis per query family.** Do not mix unrelated exposure classes in a giant Boolean query.
3. **Constrain before expanding.** Prefer `site:{scope}` or an exact identifier before broad web-wide searches.
4. **Treat snippets as leads.** Fetch the underlying public source before confirming a finding where practical.
5. **Search-engine repetition is not independent corroboration.** Bing/Google/Exa/Parallel may all index the same original page.
6. **Never interpret zero results as clean.** Record `NOT_INDEXED_OR_NOT_RETURNED` unless another authoritative control verifies absence.
7. **Do not copy exposed secret values.** Record the URL, exposure class, timestamp, bounded redacted indicator, and remediation status.
8. **New assets are candidates.** A discovered sibling domain/account/bucket is not automatically authorised target scope.

## Defensive dork families

The templates below use placeholders. Replace only with identifiers already inside the authorised scope.

### 1. Baseline indexing and forgotten content

```text
site:{domain}
site:{domain} before:{YYYY-MM-DD}
site:{domain} after:{YYYY-MM-DD}
site:{domain} -www
site:{domain} "{distinctive project or product name}"
```

Use for index inventory, stale pages, forgotten subpaths, rebrand remnants, and post-remediation rechecks.

### 2. Documents and published metadata

Run file types independently when precision matters:

```text
site:{domain} filetype:pdf
site:{domain} filetype:doc
site:{domain} filetype:docx
site:{domain} filetype:xls
site:{domain} filetype:xlsx
site:{domain} filetype:ppt
site:{domain} filetype:pptx
site:{domain} filetype:csv
site:{domain} filetype:txt
site:{domain} filetype:xml
site:{domain} filetype:json
```

Review for unintended names, email addresses, internal hostnames, usernames, client identifiers, document properties, draft content, and historical data.

### 3. Directory listings and backup artifacts

```text
site:{domain} intitle:"index of"
site:{domain} intitle:"index of" "backup"
site:{domain} intitle:"index of" "archive"
site:{domain} intitle:"index of" ".git"
site:{domain} inurl:backup
site:{domain} inurl:archive
site:{domain} inurl:old
site:{domain} inurl:tmp
```

A hit is an exposure lead. Do not recursively download directories or repositories as part of this passive workflow.

### 4. Configuration and secret-shaped exposure checks

For owned/written-authorised scope only. The purpose is to locate accidentally indexed secret-bearing files, not to harvest credentials.

```text
site:{domain} ".env"
site:{domain} filetype:env
site:{domain} filetype:ini
site:{domain} filetype:conf
site:{domain} filetype:config
site:{domain} filetype:yml
site:{domain} filetype:yaml
site:{domain} "BEGIN PRIVATE KEY"
site:{domain} "API_KEY"
site:{domain} "SECRET_KEY"
site:{domain} "CLIENT_SECRET"
site:{domain} "password="
```

If a result exposes an actual secret, **do not reproduce the value**. Record `SECRET_EXPOSURE_CONFIRMED`, redact the value, rotate/revoke it through the appropriate owner, and re-run the same dork after de-indexing/remediation.

### 5. Database/export/dump artifacts

```text
site:{domain} filetype:sql
site:{domain} filetype:db
site:{domain} filetype:sqlite
site:{domain} "INSERT INTO" filetype:sql
site:{domain} inurl:dump
site:{domain} inurl:export
```

Do not download large dumps merely because they are indexed. Confirm exposure using the minimum public evidence necessary.

### 6. Logs, debug output, and error leakage

```text
site:{domain} filetype:log
site:{domain} "stack trace"
site:{domain} "exception"
site:{domain} "debug"
site:{domain} "traceback"
site:{domain} "SQLSTATE"
site:{domain} "fatal error"
site:{domain} "warning:" 
```

Use product/framework-specific error strings only when the technology is already observed or reasonably hypothesised.

### 7. Authentication and administrative surface discovery

```text
site:{domain} inurl:login
site:{domain} inurl:signin
site:{domain} inurl:auth
site:{domain} inurl:admin
site:{domain} intitle:"login"
site:{domain} intitle:"sign in"
site:{domain} "single sign-on"
site:{domain} "SSO"
```

This is discovery only. Do not submit credentials, test passwords, bypass authentication, or interact with administrative endpoints beyond ordinary public retrieval.

### 8. API and developer-surface discovery

```text
site:{domain} "swagger"
site:{domain} "openapi"
site:{domain} inurl:api
site:{domain} inurl:graphql
site:{domain} inurl:swagger
site:{domain} inurl:openapi
site:{domain} filetype:json "openapi"
site:{domain} filetype:yaml "openapi"
site:{domain} "api documentation"
```

Correlate discovered API documentation with the public/authorised product surface. Do not assume undocumented routes are vulnerable.

### 9. Source-code and repository references

```text
"{domain}" site:github.com
"{domain}" site:gitlab.com
"{project-name}" site:github.com
"{exact-username}" site:github.com
"{exact-email}" site:github.com
```

Use the native repository search connector after discovery because Google snippets can be stale or incomplete.

### 10. Cloud/SaaS exposure candidates

Only use organisation/domain strings already in scope. Results identify **candidate assets**, not ownership proof.

```text
"{organisation}" site:s3.amazonaws.com
"{domain}" site:s3.amazonaws.com
"{organisation}" site:storage.googleapis.com
"{domain}" site:storage.googleapis.com
"{organisation}" site:blob.core.windows.net
"{domain}" site:blob.core.windows.net
"{organisation}" site:sharepoint.com
"{domain}" site:sharepoint.com
"{organisation}" site:*.notion.site
```

Because wildcard/site behavior can vary, simplify unreliable wildcard forms to exact platform/domain searches. Corroborate ownership before escalation.

### 11. Identity and username reuse

```text
"{exact-username}"
"{exact-username}" "{real-name}"
"{exact-username}" "{country-or-city}"
"{exact-username}" site:github.com
"{exact-username}" site:reddit.com
"{exact-username}" site:youtube.com
"{exact-username}" site:twitch.tv
"{exact-username}" site:steamcommunity.com
"{exact-username}" site:esreality.com
```

Every hit remains a candidate until corroborated. Same-handle collisions are common.

### 12. Exact email exposure

```text
"{exact-email}"
"{exact-email}" -site:{owned-domain}
"{exact-email}" site:github.com
"{exact-email}" site:pastebin.com
"{exact-email}" filetype:pdf
"{exact-email}" filetype:txt
```

An absence of indexed results is `NOT_OBSERVED_IN_SEARCH`, never proof that the address is private or unused.

### 13. Person/professional correlation

```text
"{full-name}" "{username}"
"{full-name}" "{organisation}"
"{full-name}" "{certification}"
site:linkedin.com/in "{full-name}"
site:github.com "{full-name}"
site:credly.com "{full-name}"
```

Do not merge same-name people without authoritative anchors.

### 14. Technology and product fingerprinting

```text
site:{domain} "{observed-product-name}"
site:{domain} "{distinctive-header-or-banner-text}"
site:{domain} inurl:wp-content
site:{domain} inurl:wp-admin
site:{domain} "powered by {product}"
site:{domain} "{framework-specific-public-string}"
```

Use only for observed/defensible technology hypotheses. A product string may reflect documentation, historical content, or a third-party integration rather than a live service.

### 15. Vulnerability/advisory correlation

```text
site:{domain} "CVE-{YYYY}-{NNNN}"
"{product}" "CVE-{YYYY}-{NNNN}"
"{organisation}" "security advisory"
"{domain}" "vulnerability"
```

This is contextual enrichment. Vulnerability mentions do not prove that the scoped environment is affected.

### 16. Historical/time-bounded discovery

```text
"{identifier}" before:{YYYY-MM-DD}
"{identifier}" after:{YYYY-MM-DD}
site:{domain} before:{YYYY-MM-DD}
site:{domain} after:{YYYY-MM-DD}
"{old-brand}" "{new-brand}"
```

Useful for handle continuity, prior employers/brands, historical subdomains, old documentation, and verifying whether remediation has propagated through indexing.

### 17. Noise suppression / entity resolution

```text
"{identifier}" -"{known-collision}"
"{identifier}" -site:{irrelevant-domain}
"{name}" "{profession}" -"{different-employer}"
"{username}" "{country}" -"{unrelated-platform}"
```

Use exclusions only after observing real noise; aggressive exclusions can hide contradictory evidence.

### 18. Image correlation

Google Images only:

```text
"{name-or-brand}" imagesize:{WIDTH}x{HEIGHT}
src:{known-image-url}
```

Use for owned brand assets, copied logos, reused public portraits, and impersonation review. Visual similarity alone is not identity proof.

## GHDB category mapping

OffSec/OWASP-style categories should be interpreted defensively as hypothesis families:

| GHDB family | PARA11AX defensive interpretation |
| --- | --- |
| Footholds | Public technology/application surface leads |
| Files containing usernames | Identity/contact exposure |
| Sensitive directories | Indexing and directory-listing exposure |
| Web server detection | Technology fingerprinting |
| Vulnerable files | Stale/public artifact exposure |
| Vulnerable servers | Candidate product/version exposure; verify independently |
| Error messages | Debug/stack/config leakage |
| Files containing juicy info | Documents/config/log metadata exposure |
| Files containing passwords | Secret-shaped exposure; redact and rotate, never harvest |
| Sensitive online shopping info | E-commerce privacy/compliance exposure |
| Network or vulnerability data | Infrastructure and scanner-report exposure |
| Pages containing login portals | Authentication-surface inventory |
| Various online devices | Candidate internet-facing device exposure |
| Advisories and vulnerabilities | CVE/product contextual enrichment |

Do **not** bulk replay GHDB against the open internet. Select only dork families that answer the current authorised hypothesis.

## Integration with Authorised OSINT Toolkit

### `defensive-osint-planning`

Create the scope object and dork plan. Record:

- authorised domains/identifiers;
- exposure classes to test;
- query budget;
- allowed public retrieval methods;
- stop conditions;
- sensitive-result handling.

### `org-attack-surface`

Use site/domain, login/admin, API/docs, technology, cloud/SaaS and public-document dorks to generate **candidate assets**. Confirm ownership before further target-directed work.

### `email-domain-security`

Use dorks only for public email/domain leakage and published mail-security documentation. DNS posture itself should be verified from DNS, not inferred from indexed pages.

### `cloud-saas-exposure`

Use organisation/domain strings to identify candidate cloud/SaaS artifacts. Search results never establish ownership by themselves.

### `defensive-exposure-analysis`

Use config/backup/log/error/directory/API/auth-surface families to discover accidental indexing. Verify with the minimum non-invasive public fetch.

### `exposure-risk-quantification`

Score a dork finding only after confirming:

- the material is actually public/retrievable;
- the scoped entity owns or controls it;
- the exposed data has security/reputation/privacy value;
- the result is current enough to matter.

### `continuous-exposure-monitoring`

Persist **query templates**, not sensitive results. A monitor should rerun only the smallest high-value query set and alert on new confirmed URLs/relationships.

### `osint-autopilot`

Dorking belongs in passive discovery and verification stages. Search results can trigger a candidate finding but never automatic exploitation.

## User Scanner integration

Google dorking and User Scanner are complementary:

```text
exact username/email
  -> Google exact-identifier dorks
  -> User Scanner
  -> union candidate profiles/accounts
  -> de-duplicate by canonical URL/platform/identifier
  -> reject collisions
  -> independently corroborate material relationships
```

Google adds historical pages, documents, snippets and cross-platform references. User Scanner adds structured platform/account discovery. Neither is a truth source.

## PARA11AX evidence contract

For each material search result preserve only:

```text
query_template_id
query_rendered
search_engine
target_anchor
retrieved_at
result_url
result_title
result_snippet_redacted
exposure_class
relationship_state
confidence
corroborating_sources
analyst_note
```

Do not store actual passwords, tokens, private keys, session cookies, full leaked databases, or unnecessary personal data in Investigation Workspace, Airtable, Notion, GitHub, or reports.

Dork output is **operator context**, not Evidence v2. It may become a confirmed OSINT finding only after source verification and ownership/entity corroboration.

## Suggested bounded MAXX query packs

### Identity pack

```text
"{username}"
"{username}" "{name}"
"{email}"
site:github.com "{username}"
site:linkedin.com/in "{name}"
```

Then invoke User Scanner for the exact username/email and reconcile results.

### Domain exposure pack

```text
site:{domain}
site:{domain} filetype:pdf
site:{domain} intitle:"index of"
site:{domain} inurl:login
site:{domain} inurl:api
site:{domain} ".env"
site:{domain} filetype:log
site:{domain} "stack trace"
```

### Remediation re-test pack

Re-run **the exact query that produced the finding**, plus:

```text
site:{exact-affected-url-prefix}
"{distinctive-exposed-string}" site:{domain}
```

Search de-indexing can lag source remediation. Record `SOURCE_FIXED_INDEX_STALE` when the live source is fixed but Google still returns an old snippet.

## Stop conditions

Stop when:

- the defensive question is answered with adequate corroboration;
- two consecutive query-family/pivot rounds add no material new asset, relationship, exposure, contradiction, or action;
- results become dominated by same-name/handle collisions;
- Google begins rate limiting/CAPTCHA behavior;
- further searching would mostly collect personal data rather than security-relevant evidence;
- scope ownership becomes unclear.

## Current references

- Google Search Help — Refine searches: https://support.google.com/websearch/answer/2466433
- Google Search Central — Search operators: https://developers.google.com/search/docs/monitor-debug/search-operators
- Google Search Central — `site:` operator limitations: https://developers.google.com/search/docs/monitor-debug/search-operators/all-search-site
- Google Search Central — indexable file types: https://developers.google.com/search/docs/crawling-indexing/indexable-file-types
- OffSec Exploit Database / GHDB background: https://www.exploit-db.com/about-exploit-db
- OWASP WSTG — search-engine reconnaissance for information leakage: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage/

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
