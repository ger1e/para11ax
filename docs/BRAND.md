<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Brand System

> **PARA11AX // PROVENANCE-FIRST CTI TERMINAL**  
> **Evidence first. Bounded always. Operational when supported.**

PARA11AX uses one terminal-first identity across the landing page, analyst Web UI, GitHub README, documentation diagrams, package/CLI references and deployment surfaces.

## Primary identity

The **terminal frame** is the primary identity element. The product should read first as a bounded phosphor terminal, not as a dashboard, SaaS card system, poster, or illustration-led interface.

The **terminal prompt** is the second primary identity element:

```text
analyst@para11ax:~$ whoami
Threat Hunter
analyst@para11ax:~$ _
```

The terminal frame and prompt must be visible whenever a surface has enough space. The compact phosphor PPI radar/wordmark is the canonical logo family; no sentinel/helmet identity owns the page hierarchy.

## Canonical visual system

The terminal language combines five rules:

1. **Void terminal plane** — `#020403` owns the canvas.
2. **Phosphor signal** — `#39FF14` owns identity, prompts, cursor, active rails, status and primary terminal borders.
3. **Signal white** — `#F7FFF6` owns primary readable content.
4. **Muted terminal gray-green** — `#8DA391` owns passive state and secondary copy.
5. **Sparse anomaly red** — `#FF2438` is reserved for failures, contradictions and deliberate anomaly cues.

| Token | Hex | Role |
| --- | --- | --- |
| `terminal-bg` | `#020403` | primary background |
| `terminal-phosphor` | `#39FF14` | identity, prompt, cursor, active state |
| `terminal-text` | `#F7FFF6` | primary content |
| `terminal-muted` | `#8DA391` | passive/secondary content |
| `terminal-alert` | `#FF2438` | anomaly, error, contradiction |

Legacy cyan, amber, alternate-green and sentinel/helmet presentation are not active branding.

## Canonical copy

Use these phrases consistently:

```text
PROVENANCE-FIRST CTI PLATFORM
EVIDENCE FIRST.
BOUNDED ALWAYS.
OPERATIONAL WHEN SUPPORTED.
OBSERVED ≠ INFERRED ≠ CONTEXTUAL
DERIVED CONTEXT ≠ EVIDENCE
OPERATOR CONTEXT ≠ EVIDENCE
ABSENCE ≠ BENIGN
IMPLEMENTED ≠ CONFIGURED ≠ PRODUCTION-VERIFIED
```

Primary product identifiers:

```text
repository: para11ax
package: para11ax
CLI: para11ax
gateway bearer: PARA11AX_TOKEN
API: /api/para11ax/*
production: https://para11ax.vercel.app
analyst UI: https://para11ax.vercel.app/app/
```

## Product truth in public copy

Public content should describe the current deterministic architecture accurately:

- Evidence v2 is the authoritative normalized evidence record.
- Provider Value Scheduler v1.0 changes deterministic attempt order only; it does not change admission, hosts, credentials or evidence semantics.
- The current IP reference path is a 24-provider workflow with a 48-call ceiling, max 4 concurrent providers, maximum two attempts/provider and 20-second request deadline.
- Intelligence Kernel v1.0 is deterministic derived context, not Evidence v2.
- Kernel language may describe evidence strength, source diversity, contradiction severity, temporal relevance, explicit one-hop pivots, coverage impact, hunt relevance and analyst priority.
- No LLM, adaptive runtime model or universal maliciousness score is part of the canonical enrichment/analysis path.
- User Scanner, native Shodan, and GreyNoise Project Swarm are separate specialist operator surfaces and are not silently promoted into Evidence v2 or Kernel reasoning.
- Canonical GreyNoise IP enrichment and GreyNoise Swarm session operations are distinct surfaces. Swarm supports bounded `search`, `get`, `unique`, `timeseries`, and explicit single-session `export` in the Web shell.
- Public copy must not claim a configured production GreyNoise credential, Sensors entitlement, Swarm entitlement, or export entitlement unless an authorized check on the exact deployed SHA proved it.
- Swarm read results can be explicitly captured as Investigation Workspace operator context; PCAP/raw exports remain explicit downloads. Operator context is not Evidence v2.

## Landing page

The landing page is one large terminal environment.

Required composition:

- compact terminal status line with product, link/auth/system state and terminal entry;
- large PARA11AX terminal/ASCII identity;
- provenance-first doctrine;
- terminal-style system overview;
- capability transcript;
- visible analyst shell example using `analyst@para11ax:~$`;
- fixed-source summary;
- terminal footer with read-only/fixed-egress doctrine.

Capability copy may mention GreyNoise Project Swarm only as a bounded specialist session surface. It must not imply that Swarm session telemetry is automatically canonical evidence or that a vendor entitlement is proven by source code.

Do not use rounded marketing cards as the primary hierarchy. Do not place decorative motion over readable terminal content.

## Analyst Web UI

The `/app` surface is a native shell plane:

```text
status line
────────────────────────────────
scrollback / evidence transcript
────────────────────────────────
analyst@para11ax:~$
```

The authenticated shell keeps status → scrollback → prompt as its DOM and visual hierarchy. Result views remain transcript sections with dotted separators. No dashboard sidebars, duplicated command launchers or generic SaaS card hierarchy.

Mobile preserves the same hierarchy in one column. Input text stays large enough to avoid browser zoom, raw JSON remains horizontally scrollable, and decorative Matrix content is edge-biased/reduced.

## Motion system

Maximum visual cue means frequent but bounded terminal motion, not flashing.

Canonical motion:

- cursor blink: `0.8–1.0 s` cycle;
- PPI/scanner sweep: approximately `1.8–4.8 s` depending on surface;
- Matrix streams: multi-depth, low-opacity cycles;
- status pulse: bounded brightness change;
- terminal-line reveal: short stagger depending on section;
- event glitch: brief, low displacement, event-triggered only.

Never use high-frequency full-screen flashes, destructive layout shifts, or motion that hides evidence. `prefers-reduced-motion: reduce` slows/removes nonessential movement while preserving content hierarchy.

## Pointer system

Browser-owned PARA11AX surfaces use the local `assets/brand/para11ax-cursor.svg` pointer through `/site-cursor.css`. Interactive chrome keeps the branded pointer; terminal output, code, form text and selectable documentation retain native text-selection semantics. The cursor layer must not load remote assets.

GitHub-hosted README and Markdown pages cannot override github.com browser cursor policy; they express the same identity through the terminal SVG family.

## Audio

No new audio is part of the landing/README/documentation identity. Existing `/app` synthesized audio behavior is independent runtime behavior and is not expanded by documentation/brand work.

## README and documentation sizing

The GitHub README uses the **same geometry and typography scale as the GER1E profile README**, while retaining PARA11AX black/phosphor/white/red semantics.

Current canonical README SVG family:

- `assets/brand/para11ax-readme-hero-v9.svg` — `720 × 360`;
- `assets/brand/para11ax-readme-architecture-v6.svg` — 720px-wide architecture panel;
- `assets/brand/para11ax-readme-semantics-v5.svg` — 720px-wide semantic-firewall panel;
- `assets/brand/para11ax-readme-footer-v2.svg` — `720 × 300`.

GER1E-normalized type scale:

- hero primary mark: **102 px**;
- panel primary headings: **22 px**;
- body/technical copy: **17 px**;
- labels/microtype: **15 px**;
- hero primary rain: **13 px**;
- hero secondary rain: **12 px**.

The old PARA11AX 16px panel-body tier is retired. README diagrams use 12px rounded outer framing, the canonical mono stack, self-contained vector content, no remote asset dependencies and a consistent 720px width. Architecture/semantic panels may be taller than the hero, but all use the same framing, padding and 15/17/22 hierarchy. The README footer is full-width rather than a small inline logo lockup.

The README uses compact numbered sections and keeps technical prose searchable. Decorative SVGs supplement—never replace—exact text contracts.

## Matrix rain

Matrix rain is atmosphere, never content hierarchy.

- green streams dominate;
- red anomaly streams are sparse;
- desktop may be dense and multi-depth;
- mobile is edge-biased and lower opacity;
- reduced motion slows/removes fall animation;
- no stream may interfere with prompt, evidence or navigation legibility.

## Typography

No bundled font files are required.

Canonical stack:

```text
ui-monospace, SFMono-Regular, Menlo, Consolas, monospace
```

Wide tracking is allowed for PARA11AX/status labels. Long technical content uses normal mono spacing for readability.

## Canonical quotation

> “You’ve got to follow the evidence… That doesn’t make it fact.”  
> — **John Kiriakou**

Use the quotation as a secondary evidence-discipline cue. Preserve the ellipsis and attribution. Do not imply endorsement.

Source context: John Kiriakou, *The Joe Rogan Experience* #2392, approximately 01:32:47–01:33:55.

## Voice

PARA11AX copy should be:

- short;
- evidence-first;
- explicit about uncertainty;
- technically precise;
- free of synthetic “AI threat score” language;
- explicit that no LLM participates in the deterministic core;
- free of claims that absence means benign;
- free of attribution by infrastructure/session proximity alone;
- explicit when a specialist operator result is contextual rather than canonical evidence;
- explicit when configuration or vendor entitlement has not been live-proven.

## Do / do not

| Do | Do not |
| --- | --- |
| make the terminal frame the visual anchor | turn pages into generic SaaS dashboards |
| keep `analyst@para11ax:~$` visible where useful | invent unrelated prompt identities |
| use phosphor for active structure | reintroduce cyan/amber brand rails |
| use red only for sparse anomaly/error cues | make red a universal maliciousness verdict |
| preserve the GER1E 720px / 15-17-22 scale | mix arbitrary README panel type sizes |
| distinguish Evidence v2 from Kernel derived context | present derived intelligence as new evidence |
| distinguish operator context from Evidence v2 | describe Swarm/Shodan/User Scanner context as provider corroboration |
| describe Swarm entitlement as external account state | infer entitlement from a configured key or READY deployment |
| retain exact technical caveats | brand away uncertainty |

## Identity boundary

The canonical public identity is intentionally singular:

- repository: `para11ax`
- package: `para11ax`
- CLI: `para11ax`
- bearer: `PARA11AX_TOKEN`
- API paths: `/api/para11ax/*`
- production URL: `https://para11ax.vercel.app`
- analyst UI: `https://para11ax.vercel.app/app/`
- Maltego artifact: `para11ax-local.mtz`

Legacy aliases and legacy visual palettes are not part of the supported contract.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>