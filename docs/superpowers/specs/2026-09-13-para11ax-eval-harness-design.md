<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Internal Eval Harness Design

> **Historical design record.** This page preserves the index and provenance for the approved 2026-09-13 eval-harness design. The verbatim original design is retained at `docs/superpowers/specs/2026-09-13-para11ax-eval-harness-design.archive.txt`. For current production architecture and normative runtime behavior, see `docs/ARCHITECTURE.md`.

Status: historical design record
Date: 2026-09-13
Implementation record: `docs/superpowers/plans/2026-09-13-para11ax-eval-harness.md`
Current operator contract: `docs/PARA11AX-EVALS.md`

The approved design keeps evaluation outside the production MCP request path. Candidate result bundles are evaluated offline against a frozen synthetic/public corpus; deterministic domain scorers emit privacy-bounded scorecards; comparison logic applies manifest-defined promotion policy; and routing changes remain explicit, reviewed source changes rather than runtime scorecard effects.

The archived text is retained byte-for-byte so the original schemas, scorer formulas, promotion thresholds, privacy boundary, CLI contract, and testing strategy remain auditable without weakening the repository-wide GER1E/PARA11AX Markdown contract.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
