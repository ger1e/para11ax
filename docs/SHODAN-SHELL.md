<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# Shodan analyst shell

PARA11AX exposes a bounded native Shodan command surface inside the authenticated analyst shell. It is a specialist operator family inside the unified command fabric documented in [SHELL.md](SHELL.md), not a second Evidence v2 enrichment pipeline and not an Intelligence Kernel data source.

## Commands

```text
shodan host <ip>
shodan search <query>
shodan count <query>
shodan stats <query> [--facets <fields>]
shodan domain <domain>
shodan info
```

Examples:

```text
shodan host 8.8.8.8
shodan search product:"FortiGate" country:HU
shodan count port:443 country:HU
shodan stats product:nginx --facets country:20,org:10
shodan domain example.com
shodan info
```

## Unified shell boundary

Shodan uses the same shared registry, parser, surface gate and pipeline runtime as the rest of the PARA11AX shell. Its command grammar remains specialized and bounded; it does not become a generic provider, HTTP or host-shell escape path. See [SHELL.md](SHELL.md) for the common grammar, internal pipeline semantics, surface visibility and hard shell limits.

GreyNoise Project Swarm is a sibling specialist operator family with a separate fixed route and vendor contract; it does not alter the Shodan grammar or credit model. See [GREYNOISE-SWARM.md](GREYNOISE-SWARM.md).

## Boundary

The browser calls only the same-origin authenticated endpoint `POST /api/para11ax/shodan`. The gateway reads `SHODAN_API_KEY` server-side and sends requests only to the fixed upstream origin `https://api.shodan.io`. The caller cannot select an arbitrary URL, host, page, HTTP method, credential, proxy, or provider destination.

Shodan operator results are rendered in terminal scrollback and leave the current Evidence v2 enrichment result unchanged. They are not promoted into Evidence v2 correlation, **Intelligence Kernel v1.0**, Decision Support, STIX, Evidence Graph, Guidance or provider voting automatically.

Compatible Shodan operator results can be explicitly recorded by Investigation Workspace through `investigation capture operator`. That operation preserves the result as contextual operator material rather than converting it into Evidence v2, provider corroboration, maliciousness, ATT&CK mapping or analyst disposition.

The canonical Evidence v2 Shodan provider is a separate adapter in the fixed provider fabric. Only that normalized provider path can contribute Shodan-origin observations to Evidence v2 and therefore to any later deterministic derived analysis. Native shell output never bypasses that boundary.

## Bounded behavior

- `host` performs one exact IP lookup and does not consume a query credit under the Shodan API credit model.
- `count` and `stats` use the count endpoint and are classified as no-query-credit operations by PARA11AX.
- `info` retrieves account/API plan and remaining-credit metadata and is classified as no-query-credit.
- `domain` is explicitly marked as consuming a query credit.
- `search` is first-page only and is marked as potentially consuming a query credit depending on Shodan plan/query behavior.
- Search results are capped and large raw banners/service bodies are removed before returning to the browser.
- `download`, arbitrary paging, caller-selected URLs and unsupported options are disabled.

The terminal surfaces returned `creditImpact` so the analyst can distinguish free, credit-consuming, and potentially credit-consuming operations.

## Authentication and configuration

The route requires the normal PARA11AX gateway bearer:

```text
Authorization: Bearer <PARA11AX_TOKEN>
```

Production configuration requires:

```text
SHODAN_API_KEY=<server-side Shodan API key>
```

Never expose or commit the Shodan key. Missing configuration fails closed with a controlled service-unavailable response. Shodan rate limiting is returned explicitly rather than converted into empty/negative evidence.

## Semantics

Shodan host, service, DNS, organization and exposure data are infrastructure/exposure context. They do not by themselves prove compromise, maliciousness, attribution, ownership, exploitability, or current reachability.

The dedicated shell surface is separate from:

1. the normal Shodan Evidence v2 provider adapter;
2. Provider Value Scheduler v1.0, which only orders already-admitted Evidence v2 adapters;
3. Intelligence Kernel v1.0, which only consumes normalized Evidence v2/correlation/coverage after provider execution;
4. GreyNoise Project Swarm, which uses its own fixed `https://api.greynoise.io` session/pivot/export route.

Neither Provider Value Scheduler v1.0 nor Intelligence Kernel v1.0 adds a Shodan shell call, changes Shodan credit behavior, or creates new egress. The deterministic core uses no LLM.

## Production proof

A successful public deployment, GreyNoise Swarm operation, or Evidence v2 Shodan provider probe does not prove native Shodan shell readiness. Shell readiness requires an authorized command on the exact deployment with `SHODAN_API_KEY` configured. Prefer `shodan info`, `shodan host <approved-ip>`, or `shodan count <approved-query>` for no-query-credit wiring checks.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>