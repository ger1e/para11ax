<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Public release checklist

This repository is public. Treat every commit, pull request, workflow artifact, issue, and release as a publication event.

#### Hard gates

Do not merge or publish a release unless all of the following are true:

- No client, employer, internal-enterprise, restricted, or otherwise non-public data is present.
- No provider credential, gateway bearer, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, User Scanner token, private key, certificate, session token, `.env` file, capture, malware sample, dump, or analysis artifact is tracked or present in reachable history.
- No real Shodan account metadata, GreyNoise account/sensor/workspace metadata, remaining-credit screenshots, account IDs, query history, session payloads, PCAP/raw exports, or credential-bearing request URLs are committed.
- Provider licensing and redistribution terms have been reviewed for any bundled schemas, fixtures, screenshots, examples, or response-derived material.
- No internal hostnames, usernames, tenant IDs, account IDs, case/ticket IDs, private URLs, project/team identifiers, sensor identifiers, or non-public infrastructure details remain.
- Example indicators, Shodan queries and GreyNoise Swarm session queries are documentation-safe public examples or synthetics; they are not copied from restricted investigations.
- Relevant Git history has been inspected, not only the current working tree.
- CI, deployment, environment-variable references, logs, artifacts, and documentation have been reviewed for unnecessary operational disclosure.
- Provider Value Scheduler v1.0 documentation does not expose credentials, secret configuration or pretend execution priority is a threat score.
- Intelligence Kernel v1.0 documentation clearly labels Kernel output as deterministic derived context, not Evidence v2, and does not imply LLM inference or universal maliciousness scoring.
- Shodan shell documentation exposes only the intended public contract: fixed `https://api.shodan.io` egress, server-side `SHODAN_API_KEY`, bounded commands/results, explicit credit semantics, and no real secret/account values.
- GreyNoise Project Swarm documentation exposes only the intended public contract: fixed `https://api.greynoise.io`, server-side `GREYNOISE_API_KEY`, `search|get|unique|timeseries|export`, bounded ranges/fields/results, explicit scope/entitlement semantics, no bulk/demo export, and no real sensor/session/payload material.

If a secret was ever committed, revoke or rotate it before history cleanup. Rewriting history does not make a still-valid secret safe.

#### Automated guardrail

Run:

```bash
npm run audit:public
```

For additional organization or client terms that must never appear in a release candidate:

```bash
PUBLIC_RELEASE_FORBIDDEN_TERMS='example-client,internal-domain.example,case-prefix' npm run audit:public
```

The audit blocks common sensitive artifact types and high-confidence credential patterns. A passing result is a guardrail, not proof that publication is safe.

#### Scheduler / Intelligence Kernel review

For changes touching Provider Value Scheduler v1.0 or Intelligence Kernel v1.0, confirm:

- the canonical provider count remains 38 unless an explicit provider change is actually part of the release;
- the IP reference workflow remains 24 providers / 48-call ceiling unless the execution contract intentionally changes;
- profile admission and scheduler execution order remain separately documented;
- scheduler descriptors do not add provider hosts, credentials, methods or dynamic evidence-dependent suppression;
- Kernel code/documentation adds no new egress, dependency, secret/environment read or persistence surface;
- Kernel conclusions are labeled derived context and do not become Evidence v2 observations, Evidence Graph evidence edges or unsupported STIX/attribution facts;
- explicit one-hop pivots retain source/evidence provenance and are not inferred from free text;
- failed/skipped providers remain coverage state rather than benign/negative threat evidence;
- no LLM/adaptive model or universal threat score is introduced;
- Decision Support/Guidance/report compatibility and failure isolation are covered by tests;
- any semantic version change that can alter analyst priority/disposition is documented and regression-tested.

#### Shodan-specific review

For changes touching the native Shodan analyst-shell surface, confirm:

- examples use documentation-safe IPs/domains/queries;
- no API key or key-bearing URL appears in docs, tests, screenshots, logs, CI output, or issue/PR text;
- `shodan download`, arbitrary paging, caller-selected URLs, and on-demand scan submission remain absent/disabled unless a future explicit design changes that boundary;
- search remains first-page only and response/banners remain bounded as documented;
- query-credit impact is documented accurately without embedding live account balances;
- Shodan operator output remains separate from Evidence v2 and Intelligence Kernel reasoning unless an explicit typed design says otherwise.

#### GreyNoise Project Swarm review

For changes touching the Swarm operator surface, confirm:

- `GREYNOISE_API_KEY` remains server-side and no key/account/sensor/workspace identifier appears in public artifacts;
- upstream destination remains fixed to `https://api.greynoise.io` and redirects remain refused;
- only `swarm search`, `swarm get`, `swarm unique`, `swarm timeseries`, and `swarm export` are exposed;
- search/pivot ranges, page values, query length, pivot fields, timeseries interval/size, session IDs and export types remain bounded/allowlisted;
- JSON read results and each single-session binary export remain capped at 4 MiB;
- bulk `/v3/sessions/export`, caller-selected endpoints/methods/headers/credentials and `scope=demo` export remain absent/disabled;
- `scope=workspace` Sensors entitlement and `scope=demo` Swarm entitlement are documented as external vendor-account state, not inferred from source/deployment/configuration;
- `search|get|unique|timeseries` results remain operator context even after explicit `investigation capture operator`;
- PCAP/raw export remains explicit download-only and is not committed, attached, screenshotted, logged, or promoted into Evidence v2 automatically;
- examples use synthetic/session placeholders and contain no real payload/network material.

#### History review

For changes touching credentials, deployment, fixtures, examples, imported data, scheduler/provider metadata, or previously private material, review at minimum:

- historical `.env*`, config, fixture, and deployment files;
- removed screenshots, captures, samples, archives, and generated artifacts;
- commit messages and PR/issue text for restricted names or identifiers;
- old CI logs and artifacts if they could contain sensitive output;
- provider terms where response-derived data or schemas may be redistributed;
- Shodan query/account output when shell integration or screenshots were developed;
- GreyNoise Swarm session queries, sensor/workspace identifiers, PCAP/raw exports, or payload-derived screenshots created during development.

#### Public-source hygiene

Keep the public repository limited to material necessary to demonstrate and operate the engineering pattern:

- architecture and threat model;
- safe schemas and synthetic examples;
- bounded provider adapters or mocks where licensing permits;
- deterministic scheduler/Kernel rules and tests without secrets/private evidence;
- bounded Shodan shell contract/tests without credentials or live account details;
- bounded GreyNoise Swarm contract/tests without credentials, live sensor/session records or packet/raw captures;
- CI and security controls;
- documentation.

Do not commit production credentials, private deployment identifiers, personal research data, commercial-client material, provider response corpora, Shodan account/query-history exports, GreyNoise sensor/session/payload exports, malware samples, or investigation artifacts.

When work originates from a private environment or restricted source, prefer a reviewed sanitized export instead of importing private Git history.

#### Deployment proof review

Repository/CI success and production deployment are separate proof states. Before claiming a feature is live:

1. read current protected `main` SHA;
2. require fresh Tooling smoke and CodeQL on the accepted merge SHA/tree;
3. read Vercel production deployment metadata;
4. verify its `githubCommitSha` equals the accepted source SHA and state is `READY`;
5. only then perform public/authenticated acceptance appropriate to the change.

A Vercel build/deployment rate limit means the new code is not deployed. Do not describe the previous READY build as containing a newer repository feature. A READY Swarm route still does not prove `GREYNOISE_API_KEY`, Sensors entitlement, Swarm entitlement, or export entitlement without an authorized live operation on that exact deployment.

#### Final review

Before merge or release, answer these independently:

1. What would a stranger learn about private people, organizations, environments, investigations, Shodan/GreyNoise account state, sensors, sessions, payloads, or operator queries?
2. Could anything here be used to access a service or reconstruct a credential?
3. Could any bundled material violate a provider or source license if redistributed?
4. Is any operational detail unnecessary to prove or operate the project?
5. Does public copy distinguish authoritative Evidence v2 from deterministic derived context and operator context, and current production from merely merged/configured code?

If any answer is uncertain, stop publication of that change until it is resolved.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>