<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Operations

#### Acceptance and proof states

Keep these states separate:

1. **Repository-proven** — exact source SHA passes repository invariants, dependency/public-release checks, Node tests, Maltego tests, Python compilation, shell/ShellCheck, and PowerShell parsing.
2. **CI-proven** — GitHub Actions reports the required checks for that exact SHA. `Tooling smoke` is the branch-required gate; CodeQL is also required by the PARA11AX QA/release process.
3. **Configured** — required runtime secrets/environment values exist. Source code cannot prove this.
4. **Deployment-proven** — Vercel metadata reports the expected exact Git SHA and `READY` state.
5. **Live-public-proven** — public unauthenticated routes return expected status/content on that deployment.
6. **Credential/provider-proven** — authenticated health/status/provider probes were actually executed against the exact deployment.
7. **User-Scanner-wired** — the isolated worker is deployed/configured and an authorized scan succeeds through the PARA11AX shell/API path.
8. **Shodan-shell-wired** — `SHODAN_API_KEY` is configured and an authorized bounded Shodan command succeeds through `/api/para11ax/shodan` on the exact deployment.
9. **GreyNoise-Swarm-wired** — `GREYNOISE_API_KEY` is configured and an authorized bounded `/api/para11ax/swarm` read succeeds for the intended scope on the exact deployment. Workspace/demo entitlement and export entitlement remain separate upstream facts.

Do not collapse these into one “production verified” claim.

#### Current verified architecture baseline — 2026-08-30

The Unified Intelligence Kernel / Provider Value Scheduler release merged to protected `main` as:

```text
11d7b861d9f626c45f44c138c8d72cee9493efdf
```

Fresh push verification on that exact SHA:

```text
Tooling smoke 1374 — PASS
CodeQL 962         — PASS
```

The merged tree introduced Provider Value Scheduler v1.0 and the IP reference Intelligence Kernel v1.0 without new providers, hosts, dependencies, egress, credential reads or persistence surfaces.

Production did **not** advance to that SHA. Vercel returned a **deployment rate limit / build-rate limit** on the Hobby plan (“retry in 24 hours”). At the documentation-refresh baseline, the latest READY PARA11AX production deployment remained:

```text
dpl_6ViU1WhZpERAbkBrmoY32Jm7xbjJ
source SHA: 2acc19f0558b1c3bbbcd96b47b8da69a25192c55
```

Therefore the Kernel/Scheduler code is repository/CI-proven but not production-deployment-proven at that baseline. Live `para11ax.vercel.app` must not be described as serving the Kernel until Vercel metadata shows an exact newer source SHA containing it. Authenticated protected enrichment was not exercised as part of that release verification.

This section is a dated proof record, not a promise that those SHAs remain the newest forever. Re-check GitHub and Vercel metadata before making a current production claim.

#### GreyNoise integration baseline — 2026-09-06

Project Swarm integration landed in three source changes after the dated Kernel/Scheduler baseline:

- PR #207 / `dfb3ef854885321f175ef588d5b8398c86baedc2` — authenticated GreyNoise v3 IP lookup with bounded Project Swarm workspace labels.
- PR #208 / `76030561a6b4b78131d6a32f5084e0620535aad7` — Web-only Swarm session `search`, `get`, and explicit single-session `export`.
- PR #209 / `ec3cac395693cc448a7bfada5ed7cd6c9ff68000` — allowlisted `unique` and `timeseries` pivots plus explicit Investigation Workspace operator capture for Swarm read results.

These source/CI facts do not prove a production GreyNoise credential or account entitlement. A READY deployment, route existence, or fail-closed unauthenticated response is not equivalent to an authorized `scope=workspace` or `scope=demo` success.

#### Provider scheduling operations

Provider Value Scheduler v1.0 changes deterministic attempt order among already-admitted providers. It does not alter profile admission.

Current IP reference invariants:

- 24-provider IP workflow;
- 48-call ceiling (24 × maximum two attempts);
- max provider concurrency 4;
- request deadline 20 seconds;
- every admitted provider remains scheduled;
- scheduler metadata failure falls back deterministically;
- no evidence-dependent source suppression;
- no LLM/runtime learning/adaptive ranking.

Scheduler metadata exposed by capability/meta surfaces is audit metadata. It must not expose credentials or be described as a threat score.

#### Intelligence Kernel operations

Intelligence Kernel v1.0 is an in-process deterministic derived-context projection over existing normalized evidence/correlation/coverage. Current production code support is IP-reference only.

Operational invariants:

- Evidence v2 remains authoritative.
- Kernel output is derived context, not provider evidence.
- no provider/network call, secret/environment read, persistence or new dependency;
- no LLM or adaptive runtime model;
- explicit one-hop pivots only from normalized relationships;
- observation timestamps drive temporal reasoning; missing time stays unknown;
- provider failures/skips affect coverage, never become benign/negative threat evidence;
- Kernel projection failure is isolated as `intelligence_projection_unavailable` and does not discard otherwise-valid Evidence v2;
- Decision Support and Guidance retain guarded legacy fallback behavior when Kernel data is absent/incompatible.

#### Local/full repository verification

From a clean checkout of exact `main`:

```powershell
git fetch origin
git checkout main
git pull --ff-only
npm run check
cd maltego
python3 -m unittest discover -s tests -v
cd ..
python3 -m compileall -q maltego
python3 -m compileall -q workers/user-scanner
```

`npm run check` includes repository invariants, public-release audit, full Node tests and executable documentation-contract checks.

#### Documentation contract maintenance

Externally meaningful canonical facts must not drift silently. Current checks cover:

- all nine Evidence v2 workflow types;
- canonical 38-provider fabric;
- Provider Value Scheduler v1.0 and IP scheduling invariants;
- Evidence Schema v2 / Intelligence Kernel v1.0 / Evidence Graph v1.0 / Guidance v1.0 boundaries;
- API route inventory, including `/api/para11ax/swarm`;
- User Scanner aliases/boundary/environment names;
- Shodan shell commands, endpoint, fixed upstream, key name, credit behavior, first-page search, Evidence v2 isolation and disabled `download`;
- GreyNoise Project Swarm `search`, `get`, `unique`, `timeseries`, `export`, scope/entitlement distinction, 4 MiB ceilings, fixed upstream, and Evidence v2 isolation;
- Maltego workflow/certificate semantics;
- canonical production identity;
- GER1E-normalized README SVG sizing/typography;
- changelog/QA coverage for externally meaningful capabilities.

When a canonical source changes, update the relevant documentation and drift test in the same PR. Do not weaken the test merely to preserve stale prose.

#### Hosted CI and deployment boundary

This public repository runs one bounded Ubuntu `Tooling smoke` job for pull requests targeting `main`, pushes to `main`, and manual dispatch. CodeQL runs separately for JavaScript/TypeScript analysis.

Vercel Git deployment is narrower than CI. A protected verified merge to `main` is not production acceptance by itself. Accept production only when deployment metadata reports that exact `main` SHA in `READY` state. A quota/build-rate rejection is a deployment failure state, not a code/test failure and not permission to pretend the previous deployment contains the new code.

#### User Scanner hosted wiring

Reference topology:

```text
Browser analyst shell
  -> https://para11ax.vercel.app/api/para11ax/user-scanner
  -> PARA11AX_USER_SCANNER_URL
  -> isolated User Scanner worker
```

Main project configuration:

```text
PARA11AX_USER_SCANNER_URL=https://user-scanner-kappa.vercel.app
PARA11AX_USER_SCANNER_TOKEN=<optional matching worker bearer>
```

Do not put worker credentials in tracked files, client JavaScript, screenshots, or examples containing real values.

#### Shodan analyst-shell operations

Reference topology:

```text
Browser analyst shell
  -> bearer-authenticated POST /api/para11ax/shodan
  -> bounded Shodan command handler
  -> SHODAN_API_KEY (server-side only)
  -> https://api.shodan.io
```

Production configuration:

```text
SHODAN_API_KEY=<server-side Shodan API key>
```

Approved shell commands:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

Operational guarantees:

- same-origin browser call only;
- fixed upstream origin `https://api.shodan.io`;
- no browser exposure of `SHODAN_API_KEY`;
- no caller-selected URLs, hosts, methods, pages, credentials, proxy routes, or arbitrary Shodan operations;
- search is first-page only;
- returned match/service arrays are bounded;
- large raw banners/service bodies are removed;
- `shodan download` is disabled;
- Shodan output stays terminal/operator context and leaves Evidence v2 / Intelligence Kernel state unchanged.

Credit classification:

- `host`, `count`, `stats`, `info` — no query credit;
- `domain` — consumes a query credit;
- `search` — may consume a query credit depending on Shodan plan/query behavior.

Treat quota/account state as time-sensitive operational state, not a repository fact.

#### GreyNoise Project Swarm operations

Reference topology:

```text
Browser analyst shell
  -> bearer-authenticated POST /api/para11ax/swarm
  -> bounded Swarm command handler
  -> GREYNOISE_API_KEY (server-side only)
  -> fixed https://api.greynoise.io
```

Production configuration:

```text
GREYNOISE_API_KEY=<server-side GreyNoise API key>
GREYNOISE_WORKSPACE_LABELS=greynoise,community,personal   # optional canonical IP-lookup scope override
```

Approved Web commands:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <allowlisted-field> [--scope workspace|demo] [--query <lucene>] [--include-counts]
swarm timeseries --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--field <allowlisted-field>] [--size <1..100>] [--interval <auto|1s|1m|1h|1d>]
swarm export <session-id> <pcap|raw-source|raw-destination>
```

Operational guarantees:

- Web-only same-origin browser call with the volatile PARA11AX bearer;
- fixed `https://api.greynoise.io` upstream and server-side `GREYNOISE_API_KEY`;
- no arbitrary destination, method, headers, credentials, bulk export, pivot field, or response-size override;
- explicit valid time range required for search/pivots;
- query text max 2,048 printable characters;
- search page size max 100; page max 10,000;
- timeseries size max 100 and interval fixed to the documented allowlist;
- JSON read results max 4 MiB; single-session binary exports max 4 MiB;
- bulk `/v3/sessions/export` is intentionally not exposed;
- `scope=workspace` depends on applicable Sensors entitlement;
- `scope=demo` depends on applicable Swarm entitlement and cannot export;
- read results may be explicitly captured as Investigation Workspace operator context, never automatic Evidence v2;
- binary export is explicit download-only and does not replace the current operator result.

See `GREYNOISE-SWARM.md` for the exact pivot field allowlist and upstream mapping.

#### Production smoke acceptance

Acceptance is against one exact source SHA. Verify deployment metadata first; reject a stale deployment.

Public QA can verify without a bearer:

- `GET /`;
- `GET /app/`;
- public `GET /api/para11ax/meta`;
- representative static/error routes;
- deployment metadata/source SHA;
- static Scheduler capability metadata where exposed.

Credential-bearing acceptance, only when explicitly authorized, adds:

- protected `/api/para11ax/health` and `/status`;
- one bounded public-source enrichment;
- one configured credentialed-source enrichment;
- for IP, confirm `intelligence.schemaVersion: "1.0"` only on a deployment whose source SHA includes Kernel v1;
- one bounded User Scanner operation when expected to be wired;
- `shodan info` / approved no-query-credit Shodan proof;
- one non-export GreyNoise Swarm read for each scope whose entitlement is being claimed;
- one workspace export only when that export entitlement is intentionally being validated;
- no bearer/API-key reflection in response bodies or errors.

If an authorized bearer is not used, report authenticated health/status/provider/User Scanner/Shodan/GreyNoise Swarm readiness as **not proven by this QA pass** rather than failed or implicitly healthy.

#### Provider readiness

Use the sequential secret-safe provider probe in an authorized environment:

```bash
para11ax providers probe --all
```

The Evidence v2 Shodan provider and native Shodan shell are separate acceptance surfaces. The canonical Evidence v2 GreyNoise IP provider and GreyNoise Swarm session route are also separate acceptance surfaces.

#### Maltego acceptance

Repository tests enforce parity between the nine server Evidence v2 workflow types and Maltego transforms. Certificate semantics remain explicit: `EnrichCertificate` adds `cert-sha256:` while `EnrichHash` retains file-hash semantics.

User Scanner, Shodan analyst-shell commands, GreyNoise Swarm session operations and Intelligence Kernel derived pivots are not silently added as new Maltego Evidence v2 transforms.

#### Browser-local workspace acceptance

Cases, snapshots, diffs, exact typed sightings, and case graphs remain browser-local IndexedDB state. Active-case state/authentication remain runtime-only. User Scanner, Shodan and GreyNoise Swarm read output are operator context; only an explicit compatible `investigation capture operator` action records that context in Investigation Workspace. Swarm packet/raw exports remain external downloads and are not automatically persisted/pinned as typed case evidence.

#### Secret handling

- Keep `.env*` except `.env.example` untracked.
- Store production secrets in Vercel/project secret storage, not Git.
- Rotate `PARA11AX_TOKEN` if exposed.
- Rotate `PARA11AX_USER_SCANNER_TOKEN` independently if enabled/exposed.
- Rotate `SHODAN_API_KEY` independently if exposed.
- Rotate `GREYNOISE_API_KEY` independently if exposed.
- Rotate affected provider credentials independently.
- Do not send raw queried indicators, identity targets, Swarm session payloads, packet data, or secrets to observability telemetry.

#### Failure behavior

Evidence v2 provider failures remain explicit, are not cached as negative evidence, and can yield partial results while successful providers continue. Scheduler budget/deadline skips remain coverage facts. Kernel projection failures do not transform provider/evidence state.

User Scanner gateway misconfiguration/worker failure/timeout use controlled errors. Shodan missing configuration fails closed; rate limiting remains explicit. GreyNoise Swarm missing configuration, entitlement/auth rejection, rate limiting, missing session, timeout, malformed/oversized response, or transport failure also stays operational. None of these states becomes benign/empty Evidence v2.

#### Parser / scheduler / Kernel / operator changes

When an Evidence v2 upstream schema changes: add a reproducing failing fixture, update minimally, increment parser version, regenerate manifest, update docs/drift guards, run full verification, and production-smoke the changed provider.

When scheduler descriptors/order change: update deterministic priority fixtures, capability metadata expectations, exact IP order/invariants, provider docs and release notes together. Admission/egress must remain separately reviewed.

When Intelligence Kernel rules/policy change: require TDD fixtures for evidence traceability, permutation determinism, failure isolation, compatibility fallbacks and report/Guidance behavior. A semantic change that can alter analyst priority/disposition requires an explicit version/release review.

When Shodan operator contract changes: update runtime tests, `SHODAN-SHELL.md`, README, API/architecture/operations/security/threat-model docs and changelog together.

When GreyNoise Swarm operator contract changes: update runtime tests, `GREYNOISE-SWARM.md`, README, API/SHELL/architecture/operations/providers/security/threat-model/investigation docs and changelog together. Scope/entitlement claims, field allowlists, download semantics and Evidence v2 separation require explicit review.

#### Public release

Treat every tracked repository artifact as public. Run `npm run audit:public` and follow `PUBLIC-RELEASE-CHECKLIST.md` before release publication. `QA-REPORT.md` records proof boundaries; current external GitHub/Vercel state must still be read during verification.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>