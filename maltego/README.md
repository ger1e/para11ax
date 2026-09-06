<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Maltego local transforms for PARA11AX

Maltego Graph Desktop talks only to the PARA11AX gateway. Vendor API credentials stay server-side; the workstation stores only `PARA11AX_TOKEN`.

#### Install

From this directory:

##### macOS / Linux — zsh or bash

```sh
./install.sh
```

##### Windows — PowerShell 5.1+

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install.ps1
```

The installer selects or installs a compatible Python (hard floor 3.10; preferred/tested 3.12), creates or repairs `.venv`, installs the pinned `maltego-trx==1.7.0` dependency, runs the integration/regression suite, stores the gateway bearer in the native user credential store, generates the MTZ, verifies its structure/security/inventory, and prints its SHA-256 and import path.

Credential backends:

- Windows: current-user DPAPI.
- macOS: login Keychain through `/usr/bin/security`.
- Linux: Secret Service/libsecret through `secret-tool` when available. There is no plaintext credential-file fallback; otherwise use an explicit process-local `PARA11AX_TOKEN`.

Import the resulting `para11ax-local.mtz` into Maltego Graph Desktop.

#### Lifecycle

macOS/Linux:

```sh
./install.sh --check
./install.sh --repair
./install.sh --update
./install.sh --uninstall
./install.sh --uninstall --delete-credential
```

Windows equivalents:

```powershell
.\install.ps1 -Check
.\install.ps1 -Repair
.\install.ps1 -Update
.\install.ps1 -Uninstall
.\install.ps1 -Uninstall -DeleteCredential
```

`--check` / `-Check` is read-only. Uninstall preserves the native credential unless deletion is explicitly requested. Re-running the normal installer is idempotent: a healthy venv is reused; stale, corrupt, or Python-3.9 venvs are rebuilt automatically.

For unattended execution, pre-supply `PARA11AX_TOKEN` to the process and use `--non-interactive` / `-NonInteractive`. Do not put the token in a repository file or shell profile.

#### Architecture

```text
Maltego Graph Desktop
        |
        | local transform (maltego-trx 1.7.0)
        v
PARA11AX client
        |
        | HTTPS + one bearer token
        v
https://para11ax.vercel.app/api/para11ax/enrich
        |
        v
Gateway provider router / Evidence v2
```

The transform layer never receives provider secrets.

#### Workflow parity

The gateway has nine canonical workflow types and Maltego covers all nine:

- `ip`
- `domain`
- `url`
- `hash`
- `cve`
- `attack`
- `asn`
- `cidr`
- `certificate`

The versioned `transform-manifest.json` is the package inventory and is verified during MTZ generation.

#### Transforms

- PARA11AX Enrich IPv4 -> `EnrichIPv4` -> `maltego.IPv4Address`
- PARA11AX Enrich IPv6 -> `EnrichIPv6` -> `maltego.IPv6Address`
- PARA11AX Enrich Domain -> `EnrichDomain` -> `maltego.Domain`
- PARA11AX Enrich DNS Name -> `EnrichDNSName` -> `maltego.DNSName`
- PARA11AX Enrich URL -> `EnrichURL` -> `maltego.URL`
- PARA11AX Enrich Hash -> `EnrichHash` -> `maltego.Hash`
- PARA11AX Enrich Certificate -> `EnrichCertificate` -> `maltego.Hash`
- PARA11AX Enrich CVE -> `EnrichCVE` -> `maltego.Phrase`
- PARA11AX Enrich MITRE ATT&CK -> `EnrichATTACK` -> `maltego.Phrase`
- PARA11AX Enrich ASN -> `EnrichASN` -> `maltego.Phrase` input such as `AS3333`; graph output uses `maltego.AS` where appropriate
- PARA11AX Enrich CIDR -> `EnrichCIDR` -> `maltego.Phrase` input such as `192.0.2.0/24` or `2001:db8::/32`

Certificate semantics are explicit. A raw SHA-256 selected through `EnrichCertificate` is transported to the gateway as `cert-sha256:<fingerprint>`. The same raw value selected through `EnrichHash` remains a file-hash lookup. The client does not guess certificate semantics from a bare hash.

Transforms map normalized relationships, malware-family/actor context and graphable provider attributes. Evidence v2 additionally renders bounded Phrase nodes for provider provenance, corroboration, contradictions, freshness, huntability and separate KEV/EPSS/CVSS axes. Integrity fingerprints and parser versions are graphable; raw upstream hashes are deliberately not emitted as Maltego properties.

ATT&CK TAXII results are knowledge/mapping context, not IOC reputation or a maliciousness vote. Certificate metadata is contextual evidence, not an automatic malicious verdict. CIDR remains a Phrase because no stable built-in network-prefix entity is assumed. ASN uses the stable AS entity when the mapper can do so without changing the input contract.

#### Specialist operator surfaces are not Maltego transforms

Maltego parity tracks the nine canonical Evidence v2 workflow types only. PARA11AX also has bounded specialist operator families in the unified shell; these do not become extra Maltego transforms or extra Evidence v2 providers.

GreyNoise is intentionally split into two surfaces:

1. canonical GreyNoise IP enrichment can participate in `EnrichIPv4` / `EnrichIPv6` through the fixed Evidence v2 provider path when the workflow admits it;
2. GreyNoise Project Swarm session operations are **WEB ONLY** specialist commands: `swarm search`, `swarm get`, `swarm unique`, `swarm timeseries`, and `swarm export`.

Swarm session/pivot results are operator context and are not automatically Evidence v2. PCAP/raw exports are explicit browser downloads and are not Maltego entities or automatic graph evidence. The Maltego client never receives `GREYNOISE_API_KEY` and does not call `/api/para11ax/swarm`.

The same separation applies to native Shodan shell commands and User Scanner. See [`../docs/SHELL.md`](../docs/SHELL.md), [`../docs/GREYNOISE-SWARM.md`](../docs/GREYNOISE-SWARM.md), and [`../docs/SHODAN-SHELL.md`](../docs/SHODAN-SHELL.md).

#### Non-secret configuration

```text
PARA11AX_URL=https://para11ax.vercel.app
MALTEGO_MAX_ENTITIES=50
MALTEGO_INCLUDE_PROVIDER_NODES=false
```

`MALTEGO_MAX_ENTITIES` is bounded to 1-250. Evidence-v2 provenance nodes are emitted when an integrity fingerprint exists; `MALTEGO_INCLUDE_PROVIDER_NODES=true` also forces provider evidence nodes for legacy/attribute-rich responses.

Secret resolution order:

1. Explicit process-local `PARA11AX_TOKEN` environment variable.
2. Native OS credential backend configured by the installer.

No provider API secret is stored in this directory or in the generated MTZ.

#### Security behavior

- Remote gateway URLs must use HTTPS; HTTP is accepted only for localhost development.
- Redirects are refused so the bearer token cannot be forwarded to another host.
- Response bodies are capped at 2 MB.
- Gateway errors do not include bearer-token values.
- Local graph expansion is capped at 250 and deduplicated.
- Provider failures are surfaced as partial-result messages rather than terminating successful enrichment from other providers.
- MTZ validation rejects path traversal, symlinks, duplicate entries, excessive archive sizes, loopback/dev gateway references, missing transform inventory and credential identifiers.
- Vendor API credentials never cross the gateway boundary.
- Specialist operator credentials such as `SHODAN_API_KEY` and `GREYNOISE_API_KEY` remain server-side and are not part of the Maltego configuration contract.

#### CI verification

The authoritative repository `Tooling smoke` workflow runs one bounded Ubuntu job. It executes the Maltego Python regression suite, compiles the Python package, validates the Unix installer with bash/ShellCheck, and parses the Windows PowerShell installer syntax. Platform-specific installer behavior remains covered by the repository's static/regression contract without claiming recurring hosted macOS/Windows runners.

#### Developer commands

Normal users should use the installer. For development/debugging only:

macOS/Linux:

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python project.py mtz
.venv/bin/python bootstrap.py --check
```

Windows:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe project.py mtz
.\.venv\Scripts\python.exe bootstrap.py --check
```

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>