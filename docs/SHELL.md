<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX unified shell

PARA11AX exposes one declarative command fabric to the browser analyst terminal and the local Node CLI. Both surfaces use the same command registry, parser, pipeline runtime, help metadata, aliases and completion model. Surface-specific executors perform only the effects that are explicitly registered for that surface.

This is not an operating-system shell. Commands resolve only to registered PARA11AX handlers and safe internal transforms.

## Surfaces

- **Web** — the authenticated browser terminal at `analyst@para11ax:~$`. Authentication is volatile and memory-only. Browser-local cases use the existing IndexedDB workspace.
- **CLI** — `para11ax ...` through `bin/para11ax.mjs`. It shares the same grammar/runtime but can expose explicitly registered local administrative and filesystem report operations.
- **WEB ONLY** — browser presentation, local case workspace, Investigation Workspace persistence/capture, clipboard/download, GreyNoise Project Swarm, and session controls that have no Node equivalent.
- **CLI ONLY** — bounded local administration, provider probing, report filesystem compilation/diff and manifest projection.

`help` and `man` can describe surface-restricted commands. Completion omits commands unavailable on the active surface.

## Canonical namespaces

The live registry is the command taxonomy source. The public namespaces are:

```text
discovery
session
system
intel
provider
osint
result
case
mission
investigation
report
export
terminal
transform
```

Use `commands`, `help`, `man`, `apropos`, `which`, `aliases`, `capabilities` and `limits` to discover the current registered surface instead of relying on a memorized static command list.

## Grammar

A command line is parsed by the PARA11AX tokenizer, not by a host shell.

```text
command [argument ...] | transform [argument ...] | transform [argument ...]
```

Single and double quotes preserve whitespace. Backslash escaping is supported. A native `|` separates registered PARA11AX pipeline stages.

Examples:

```text
enrich 8.8.8.8 | result evidence | head 5
provider list | where active == true | fields name credentialMode | sort name
result relationships | unique target | head 20
report text | grep "HUNT" | head 20
```

In a host shell, quote or escape the pipe so the literal `|` reaches PARA11AX when using the Node CLI. For example:

```text
para11ax 'provider list | head 5'
```

or use the platform-equivalent escaping needed to pass a literal pipe token. PARA11AX never delegates the pipeline to Bash, PowerShell, `cmd.exe` or another host interpreter.

## Hard pipeline limits

All stages are sequential, typed, cancellable and fail-fast. Current hard ceilings are:

- 12 stages per pipeline.
- 1,000 records per bounded collection.
- 2,000,000 intermediate bytes per typed stage output.
- 512,000 rendered bytes for the final terminal value.
- 10,000 text lines.

Limit violations return `OUTPUT_LIMIT`; they are not silently expanded. Browser cancellation maps to `OPERATION_ABORTED`.

## Discovery and session

Core discovery:

```text
help [command]
man <command>
commands [namespace] [--all]
apropos <term>
which <command>
aliases
capabilities [type|provider|surface]
limits
```

Session commands include `login`, `auth status`, `auth clear`, `whoami`, `session`, `history`, `history clear`, `disconnect`, `uptime` and `version`. `reboot` is **WEB ONLY**.

`login` never accepts an inline bearer. The Web terminal switches to a hidden secret prompt; the bearer remains memory-only and is excluded from history, command metadata, output and structured error context.

## System

Shared read-only system commands include:

```text
system health        # alias: health
system status        # alias: status
system meta          # alias: meta
system policy
system limits
system capabilities
```

The following are **CLI ONLY** local administrative operations:

```text
system doctor        # alias: doctor
system setup         # alias: setup
system repair        # alias: repair
system release verify
system maltego check
```

These are fixed registered workflows, not generic local command execution.

## Intelligence

Canonical enrichment remains bounded by fixed observable classification, provider admission, scheduler policy and Evidence v2 semantics.

```text
enrich <observable> [--fast|--standard|--full]
intel <observable>
intel ip <observable>
intel domain <observable>
intel url <observable>
intel hash <observable>
intel cve <observable>
intel asn <observable>
intel cidr <observable>
intel certificate <observable>
batch <observable> [observable ...]
profile [fast|standard|full]
normalize <observable>
type <observable>
validate <observable>
```

`scan` and `pivot` remain enrichment aliases. Typed `intel` front doors validate the requested observable type before provider work. `normalize`, `type` and `validate` are pure local classifier operations.

## Provider commands

Provider discovery and execution are registry- and policy-bound:

```text
provider list
provider show <provider>
provider status [provider]
provider capabilities <provider>
provider coverage <observable-type>
provider run <provider> <observable>
```

`provider probe <provider|all>` and `provider env-template` are **CLI ONLY**. Legacy `providers list`, `providers probe` and `providers env-template` spellings remain registered aliases where applicable.

`provider run` is not generic HTTP. The provider name must resolve to an active registered provider. The browser sends only the provider identity and observable through the same-origin authenticated named-provider route. Provider fixed hosts, HTTPS policy, methods, credential mode, supported observable types, cost/admission metadata, timeout, response ceiling, concurrency, retry and distribution policy remain authoritative.

Caller overrides such as `--host`, `--method`, `--credential`, arbitrary URLs, custom headers, custom proxies, parser replacement or timeout widening are rejected before provider/fetch execution.

### Fixed provider shorthands

The following front doors pin immutable provider identities and use the same bounded named-provider execution path:

```text
vt <observable>              # VirusTotal
gn <observable>              # GreyNoise
otx <observable>             # OTX
urlscan <observable>         # urlscan.io
threatfox <observable>       # ThreatFox
malwarebazaar <observable>   # MalwareBazaar
rdap <observable>            # RDAP
epss <observable>            # FIRST EPSS
kev <observable>             # CISA KEV
nvd <observable>             # NVD
censys <observable>          # Censys
```

These aliases do not bypass provider policy and do not receive provider credentials in the browser. `gn` remains canonical GreyNoise IP enrichment through Evidence v2; it is not an alias for the Project Swarm session surface.

## OSINT specialist commands

`osint` is reserved for bounded specialist operator surfaces rather than generic network access.

User Scanner:

```text
user-scanner email <target> [options]
user-scanner username <target> [options]
osint username <target> [options]
identity username <target> [options]
```

Shodan:

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

Shodan is a specialized bounded operator family inside this unified command fabric. Its operator result remains separate from the current Evidence v2 result. Exact credit and semantic boundaries are documented in [SHODAN-SHELL.md](SHODAN-SHELL.md).

GreyNoise Project Swarm is **WEB ONLY** and uses the same volatile gateway bearer with a server-side GreyNoise credential:

```text
swarm search --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--page <1..10000>] [--page-size <1..100>]
swarm get <session-id> [--scope workspace|demo]
swarm unique --from <ISO-8601> --to <ISO-8601> --field <field> [--scope workspace|demo] [--query <lucene>] [--include-counts]
swarm timeseries --from <ISO-8601> --to <ISO-8601> [--scope workspace|demo] [--query <lucene>] [--field <field>] [--size <1..100>] [--interval <auto|1s|1m|1h|1d>]
swarm export <session-id> <pcap|raw-source|raw-destination>
```

`swarm search`, `swarm get`, `swarm unique`, and `swarm timeseries` produce bounded operator records. They may be explicitly captured as Investigation Workspace operator context, but they are not automatically promoted into Evidence v2. `swarm export` performs one explicit bounded browser download and never becomes Evidence v2 or an automatic investigation attachment. Scope, entitlement, field allowlist, response ceilings and fixed upstream mapping are documented in [GREYNOISE-SWARM.md](GREYNOISE-SWARM.md).

## Mission workspace

The mission family is shared by Web and CLI. It drives one deterministic, volatile workspace through client relevance, hunt construction, conservative KQL validation, bounded result analysis and a ServiceNow-ready projection:

```text
mission new
mission show
mission profile set '<json>'
mission context set '<json>'
mission relevance
mission hunt build '<json>'
mission kql validate '<query>'
mission result analyze
mission servicenow
mission export
mission import
mission clear
```

In Web, `mission profile set`, `mission context set`, `mission hunt build`, `mission result analyze` and `mission import` open an explicit local file picker when inline content is omitted. `mission export | download` is the only browser persistence action. The workspace otherwise remains in memory; `disconnect` and `reboot` clear it, while `auth clear` does not.

The CLI accepts inline profile/context/hunt JSON and KQL. File/result/import transports are explicit and bounded:

```text
para11ax mission import --file mission.json '|' mission show
para11ax mission result analyze --file results.csv
para11ax mission import --stdin
```

`--stdin` is read only when that exact transport is requested. Input is capped at 2 MiB. Mission export emits a canonical `para11ax-mission.json` artifact and import reconstructs derived fields, rejecting tampered or structurally invalid bundles.

KQL is validated but never executed. ServiceNow output is a projection only: no ticket is submitted, no credential is read, and analyst approval remains mandatory. Mission commands add no provider call, model call, server-side persistence or Evidence v2 mutation. Full semantics are documented in [ANALYST-MISSION-PACK.md](ANALYST-MISSION-PACK.md).

## Result and evidence

Result commands consume the current enrichment when invoked without pipeline input, or the typed upstream enrichment when composed in a pipeline.

```text
result summary
result request
result evidence
result facts
result providers
result failures
result contradictions
result corroboration
result references
result relationships
result coverage
result correlation
result graph
result guidance
result decision
result attacks
result hunts
result telemetry
result freshness
result raw
view <overview|evidence|correlation|relationships|coverage|raw>
```

Legacy direct aliases such as `overview`, `evidence`, `correlation`, `relationships`, `coverage`, `raw`, `failures`, `contradictions`, `corroboration`, `references` and `providers` remain registered. Evidence Graph and Guidance are read from the authoritative enrichment envelope rather than recomputed by the shell.

## Case workspace

The case family is **WEB ONLY** because its persistence boundary is the browser-local workspace:

```text
case new <title>
case open <id>
case close
case list
case show
case refresh [--stale]
case import
case export
case find <type> <value>
case pins
case notes
case timeline
case graph
case pin
case unpin <type> <value>
case note <text>
case diff
```

Legacy `pin`, `unpin`, `note` and `diff` aliases remain available. Case commands do not create a second shell parser or server-side case persistence path.

## Reports

Shared in-memory report projections:

```text
report show
report quality
report text
report html
report pdf
report csv
report kql
report navigator
report stix
report evidence
```

On Web, report projections remain in memory until an explicit registered download action consumes an artifact. The browser cannot provide arbitrary filesystem paths.

The following are **CLI ONLY**:

```text
report compile <snapshot> <output-dir> [preset]
report diff <before> <after>
report manifest
```

`report compile` and `report diff` retain the existing bounded filesystem/report compiler contract. Filesystem effects are available only to descriptors explicitly declaring that side effect.

## Export

```text
json [save]
stix
copy <observable|report|json|request-id>   # WEB ONLY
download <artifact>                       # WEB ONLY
```

JSON, STIX and report exports preserve their existing semantic and quality gates. Browser downloads use explicit registered artifacts; there is no `>` or `>>` redirect equivalent.

## Terminal commands

Safe virtual/local display commands include:

```text
clear            # WEB ONLY; alias cls
echo [text]
printf <text>
date
hostname
pwd
uname
id
theme            # WEB ONLY
sound <on|off>   # WEB ONLY
volume <0-100>   # WEB ONLY
```

`pwd`, `hostname`, `uname` and `id` describe the PARA11AX virtual/session environment. They do not expose an arbitrary host process environment or operating-system shell.

## Internal transforms

Structured transforms:

```text
where
select
fields
sort
unique
count
group
pluck
head
tail
jsonpath
```

Text transforms:

```text
grep
wc
uniq
```

Transforms are in-process PARA11AX functions. Dotted field paths are bounded; `jsonpath` supports only bounded dotted keys/numeric indices and is not an expression evaluator. Text transforms do not invoke host binaries.

## Security exclusions

The unified command fabric deliberately rejects host-shell semantics before command execution. Unsupported syntax includes:

- backticks and command substitution.
- `$()` command substitution.
- `&&` and `||` host-shell chaining.
- semicolon command chaining.
- input/output redirect operators such as `<`, `>` and `>>`.
- arbitrary OS command execution or subprocess escape.
- `eval`, dynamic `Function`, dynamic host-command dispatch or command substitution.
- generic `sudo`, `ssh`, `curl`, `wget`, `exec` or `source` command roots.
- arbitrary URL fetching or caller-selected provider hosts.
- provider host/method/credential/policy overrides.
- browser credential persistence or credential reflection in errors/history/output.
- generic filesystem primitives or browser filesystem writes.

There is no arbitrary OS shell escape hatch. Export and download behavior is represented by explicit registered commands instead of redirects.

## Error model

Stable shell error codes include command/syntax/argument errors, pipeline type mismatch, authentication/capability/surface/provider failures, policy/quota denial, output limits, aborts and normalized upstream failures. Unexpected executor exception text is not reflected to the caller. Secret-bearing structured error context is recursively redacted.

## Examples

Discovery:

```text
commands provider
apropos evidence
which gn
man report compile
limits
```

Bounded enrichment and evidence projection:

```text
enrich 203.0.113.10 --standard | result evidence | where kind == malicious | head 10
```

Policy-bound direct provider lookup:

```text
vt 203.0.113.10 | result evidence | fields provider kind confidence
```

Provider coverage without execution:

```text
provider coverage ip | fields name credentialMode costClass | sort name
```

Bounded GreyNoise Swarm pivot:

```text
swarm unique --from 2026-09-05T00:00:00Z --to 2026-09-06T00:00:00Z --field source.ip --include-counts
investigation capture operator
```

Current-result investigation:

```text
result contradictions | head 20
result graph
result guidance
result hunts | fields title mitre kql
```

Report projection:

```text
report text
report csv | download
```

The exact currently registered command set is always discoverable from `help`, `commands`, `man`, `apropos`, `which`, `aliases`, `capabilities` and `limits`.

## Investigation Workspace v2

```text
investigation new "Fortinet access review"
investigation scope set '<profile-and-context-json>'
investigation observable add ip 203.0.113.10
investigation capture evidence
investigation capture operator
investigation relevance
investigation hunt build '<hunt-json>'
investigation kql validate '<query>'
investigation result import
investigation disposition set '<disposition-json>'
investigation status
investigation report
investigation servicenow
investigation timeline
investigation export
```

`inv` is an exact alias for `investigation`. Browser import/result commands use explicit hidden file pickers; cancellation performs no mutation. CLI inspection and canonical transport are pure operations and require exactly `--file <path>` or `--stdin`. Browser-local new/open/list/capture/clear operations are unavailable on CLI.

`investigation capture evidence` accepts only the current compatible Evidence v2 enrichment. `investigation capture operator` accepts compatible current Shodan, User Scanner, or GreyNoise Swarm read results as contextual operator material. Operator capture never promotes that material into Evidence v2. Swarm binary export is not an operator-capture input.

Mutation receipts contain investigation ID, revision, invalidated artifacts, phase, and readiness. `NO_EVIDENCE_IDENTIFIED` is distinct from `BENIGN_EXPLAINED`; the latter requires a rationale plus a linked current artifact or note. KQL execution and ServiceNow submission remain external analyst actions.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>