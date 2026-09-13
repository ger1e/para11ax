<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Internal Eval Harness Implementation Plan

> **Historical design record.** This page preserves the index and provenance for the approved 2026-09-13 implementation plan. The verbatim original plan is retained at `docs/superpowers/plans/2026-09-13-para11ax-eval-harness.archive.txt`. For current production architecture and normative runtime behavior, see `docs/ARCHITECTURE.md`.

Status: historical implementation record
Original approval/base commit: `a0fc76901bb71e7b180c5868fac065eab2e8f8db`
Design record: `docs/superpowers/specs/2026-09-13-para11ax-eval-harness-design.md`
Current operator contract: `docs/PARA11AX-EVALS.md`

The approved plan specified a provider-neutral, deterministic, offline evaluation harness with a frozen synthetic nine-domain corpus, pure scorers, privacy-bounded scorecards, manifest-driven promotion gates, explicit human-review state, an offline CLI, documentation, and exact-head CI verification. Production routing remains separately reviewed source policy and has no runtime dependency on eval scorecards.

The archived text is retained byte-for-byte so the original TDD steps, thresholds, file layout, commit instructions, and completion gate remain auditable without weakening the repository-wide GER1E/PARA11AX Markdown contract.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
