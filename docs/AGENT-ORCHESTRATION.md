<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
# PARA11AX Agent Orchestration Policy

Status: normative for agent/harness integrations
Benchmark snapshot: 2026-09-13
Runtime boundary: host/agent layer only

PARA11AX remains a deterministic CTI MCP server. The Intelligence Kernel, Evidence v2, provider orchestration, hunt generation, and provenance paths do not call an LLM. This policy governs external agent/ChatGPT hosts using PARA11AX.

## 1. Drift-resistant state

Every long-running task gets one canonical `AgentState` from `src/core/agent-state.js`.

Durable source of truth:
- objective;
- task class and risk;
- explicit constraints;
- accepted decisions;
- retrievable artifact references;
- next actions;
- revision, epoch, invariant hash, and full-state hash.

Raw transcripts, copied tool results, search logs, scratch reasoning, and recursive summaries are not durable state.

Rules:
1. Never silently rewrite objective or constraints. Use explicit reducer actions so the epoch advances.
2. Verify the intent invariant hash and full-state hash on state import/checkpoint boundaries, and verify the compact handoff hash on handoff import. A mismatch fails closed.
3. Keep accepted decisions append-only unless an explicit scope change supersedes them.
4. Hand off durable state plus references, not the whole transcript. The handoff carries both an independently verifiable handoff hash and the source-state hash for provenance linkage.
5. Prefer commit SHAs, file paths, URLs, query/incident IDs, and evidence hashes over pasted payloads.
6. After context reset, reconstruct from canonical state plus just-in-time retrieval, never conversational memory.
7. Do not declare completion from context alone. Re-check objective, next actions, artifacts, and external verification.

Anthropic's context-engineering guidance independently recommends high-signal context, just-in-time retrieval, clearing stale tool results, and preserving important decisions. Its long-running-agent work found compaction alone insufficient and used persistent progress plus git history for recoverable fresh sessions.

Sources:
- https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents
- https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents

Recent practitioner reports describe the same failure mode: opaque compaction loses constraints/status, while external checkpoints and smaller reconstructed working sets reduce re-exploration. These are operational anecdotes, not benchmark evidence.

Examples:
- https://www.reddit.com/r/ClaudeAI/comments/1uc6jp5/how_do_agents_avoid_context_drift/
- https://www.reddit.com/r/LocalLLaMA/comments/1wbgqnp/is_anyone_working_on_conversation_compaction/
- https://www.reddit.com/r/LocalLLaMA/comments/1rr5fo5/why_ai_coding_agents_waste_half_their_context/

## 2. Context and token policy

Use `planContextBudget()` before large requests and `selectContextItems()` when pruning.

Default context accounting:
- reserve the requested `maxOutputTokens` once;
- reasoning tokens are inside that output allowance on current OpenAI Responses APIs, so do not subtract a second reasoning reserve;
- reserve 5% context headroom by default, tunable by caller/internal evals;
- allocate the remaining input budget as a priority guide: invariants 12%, decisions 12%, active work 24%, evidence 30%, raw tool output 14%, scratch remainder.

The percentages are ceilings/priority guidance, not fill targets. Unused context is preferable to low-signal context. When provider tokenizer counts are available, pass exact per-item token counts; `estimateTokens()` is only a conservative fallback.

Evict in this order under pressure:
1. scratch;
2. reproducible raw tool output;
3. stale/redundant working notes;
4. duplicated evidence bodies after preserving retrievable references.

Never evict objective, constraints, or accepted decisions. If durable state alone cannot fit, split the task instead of lossy-compressing the task contract.

For very large working sets (default threshold: 250k input tokens), prefer durable state plus just-in-time retrieval over preloading everything. For long-running work, checkpoint and reset cleanly rather than repeatedly summarizing summaries.

OpenAI token-accounting reference:
- https://platform.openai.com/docs/api-reference/responses

## 3. Vendor-neutral routing

`src/core/model-routing.js` routes by task properties, not model brand.

| Task class | Tier | Effort | Review |
| --- | --- | --- | --- |
| simple transform / formatting | economy | low | no |
| routine research / analysis | balanced | medium | risk-dependent |
| coding / debugging | frontier | high | high-risk/repeated failure |
| security analysis | frontier | high | different-family reviewer when high risk |
| long-context synthesis | frontier | high | risk-dependent |
| deep reasoning | frontier_max | max | independent |
| explicit review | frontier | high | different family |

Escalation:
- zero failures: base route;
- one material failure: minimum frontier/high;
- two or more: frontier_max/max plus independent different-family review;
- high-risk work cannot be cost-demoted below frontier/high and requires independent review;
- when possible, use a reviewer from another model family to reduce correlated failure modes.

Cost sensitivity only demotes low-risk, low-complexity work. Latency sensitivity only lowers effort on low-risk work.

## 4. Deployable model mapping, 2026-09-13

This mapping has two gates: capability and verified availability. A public benchmark result does not prove the model is exposed in the operator's API/account.

Current official OpenAI API catalog mapping:

| Tier / workload | Deployable default | Rationale |
| --- | --- | --- |
| economy: extraction, normalization, formatting, high-volume low-risk transforms | GPT-5.6 Luna low | OpenAI positions Luna for cost-sensitive high-volume workloads. |
| balanced: routine research/analysis where quality still matters | GPT-5.6 Terra medium | OpenAI positions Terra as the intelligence/cost balance. |
| frontier: complex CTI synthesis, coding, security analysis | GPT-5.6 Sol high | OpenAI's documented flagship for complex reasoning/coding; 1.05M context. |
| frontier_max: deep reasoning or repeated failure | GPT-5.6 Sol max | Highest documented effort on the currently listed flagship API model. |

Official source:
- https://platform.openai.com/docs/models

Benchmark-advisory alternatives:
- Artificial Analysis v4.3 currently reports GPT-6 Astra max tied with Claude Fable 5.1 max for the Intelligence Index lead and tied at 62 on its Coding Agent Index, ahead of GPT-5.6 Sol at 55 for coding. If Astra is actually exposed in the target runtime/API, validate availability and internal evals before mapping `frontier_max` to it.
- Claude Fable 5.1 high/max is a strong different-family reviewer candidate where available. Use a different-family reviewer for error diversity, not because public benchmarks prove statistical independence.

Independent benchmark sources:
- https://artificialanalysis.ai/articles/benchmarking-gpt-6-astra
- https://artificialanalysis.ai/articles/artificial-analysis-intelligence-index-v4-3
- https://artificialanalysis.ai/agents/coding-agents/comparisons/claude-code-vs-codex
- https://artificialanalysis.ai/articles/claude-fable-5-1

Benchmark caution: model scores depend on harness, tool access, effort, and benchmark version. The harness is part of the evaluated system. Never hard-code a leaderboard ordering as permanent routing logic.

## 5. Refresh procedure

Refresh the advisory mapping when:
- a new frontier model is released;
- a benchmark index version changes;
- provider availability/pricing changes materially;
- a better task-specific benchmark appears;
- internal PARA11AX evals disagree with public rankings.

For every candidate record model+effort, family, availability, context, task-specific score, token use/task, cost/task, latency where relevant, harness/tool configuration, and snapshot date. Feed normalized scores to `rankModelCandidates()`. Change generic routing only when the policy itself changes.

## 6. Internal PARA11AX eval target

Public leaderboards are priors. Prefer a frozen internal eval corpus for:
- CTI article to structured intelligence extraction;
- provenance correctness and unsupported-claim rate;
- IOC vs IOA/TTP distinction;
- ATT&CK mapping precision;
- KQL validity against supported schemas;
- evidence retention through handoff/context reset;
- constraint retention after long tool traces;
- representative repo coding tasks;
- token/cost per successful task.

A generic coding benchmark does not prove a model is the best CTI analyst. Humanity continues to require domain-specific evaluation. Tragic, but manageable.

## 7. Completion gate

A task is complete only when:
1. canonical objective is satisfied;
2. required next actions are empty;
3. state import and both state hashes validate;
4. compact handoffs validate their own handoff hash and retain the source-state hash;
5. referenced artifacts exist;
6. task-specific verification has been rerun on the final state;
7. required high-risk review passed;
8. final reporting separates verified evidence from inference and residual limitations.

For repository changes, the authoritative signal is CI/status on the exact final head SHA, never an earlier run or the agent's memory of one.

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>
