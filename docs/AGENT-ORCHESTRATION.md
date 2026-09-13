# PARA11AX Agent Orchestration Policy

Status: normative for agent/harness integrations
Benchmark snapshot: 2026-09-13
Runtime boundary: host/agent layer only

PARA11AX remains a deterministic CTI MCP server. The Intelligence Kernel, Evidence v2, provider orchestration, hunt generation, and provenance paths do not call an LLM. This document defines how an external agent or ChatGPT host should preserve task state, allocate context, and choose a model when using PARA11AX.

## 1. Non-negotiable invariants

Every long-running task gets one canonical `AgentState` from `src/core/agent-state.js`.

The durable source of truth is:

- objective;
- task class and risk;
- explicit constraints;
- accepted decisions;
- retrievable artifact references;
- next actions;
- revision, epoch, and invariant hash.

Raw transcripts, copied tool results, search logs, scratch reasoning, and recursively generated summaries are not durable state.

Rules:

1. Do not silently rewrite the objective or constraints. Use the explicit reducer actions so the epoch advances and the scope change is auditable.
2. Check the invariant hash at import, checkpoint, and handoff boundaries. A mismatch fails closed.
3. Treat accepted decisions as append-only unless a later explicit scope change supersedes them.
4. Hand off durable state and references, not the entire transcript.
5. Prefer retrievable identifiers such as commit SHAs, file paths, URLs, query IDs, incident IDs, and evidence hashes over pasted payloads.
6. After a context reset, reconstruct the working set from canonical state plus just-in-time retrieval. Do not reconstruct intent from conversational memory.
7. Never declare completion from conversational context alone. Verify against the task's objective, next actions, artifacts, and external test/status evidence.

This is intentionally stricter than generic auto-compaction. Anthropic's context-engineering guidance recommends keeping high-signal context tight, using just-in-time retrieval, clearing old tool results, and preserving architectural decisions during compaction. Its long-running-agent work also found compaction alone insufficient and used persistent progress state plus git history to make fresh sessions recoverable.

Sources:
- https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents
- https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents

Community reports point in the same direction: long sessions frequently degrade after opaque compaction, while durable external state, checkpoints, and narrower working sets reduce re-exploration. Treat these reports as operational anecdotes, not benchmark evidence.

Examples:
- https://www.reddit.com/r/ClaudeAI/comments/1uc6jp5/how_do_agents_avoid_context_drift/
- https://www.reddit.com/r/LocalLLaMA/comments/1wbgqnp/is_anyone_working_on_conversation_compaction/
- https://www.reddit.com/r/LocalLLaMA/comments/1rr5fo5/why_ai_coding_agents_waste_half_their_context/

## 2. Context and token policy

Use `planContextBudget()` before assembling a large prompt and `selectContextItems()` when pruning.

Default reservation for a model context window:

| Bucket | Share / rule |
| --- | ---: |
| Requested output | explicit maximum |
| Reasoning reserve | 18% of total context |
| Safety/headroom reserve | 8% of total context |
| Invariants | 12% of usable input budget |
| Accepted decisions | 12% |
| Active work | 24% |
| Evidence | 30% |
| Raw tool output | 14% |
| Scratch | remainder, normally 8% |

These are guardrails, not a reason to fill the window. Empty budget is better than irrelevant tokens. Context has diminishing marginal value and can become actively harmful when it buries the working set.

Eviction order under pressure:

1. scratch;
2. reproducible raw tool output;
3. stale/redundant working notes;
4. duplicated evidence bodies after their retrievable references are preserved.

Never evict the objective, constraints, or accepted decisions. If durable state alone does not fit, fail closed and split the task instead of lossy-compressing the task contract.

For working sets above 250k tokens, default to durable state plus just-in-time retrieval rather than preloading all potentially relevant material. For long-running work, prefer checkpoints and clean context resets over repeated summary-of-summary compaction.

## 3. Routing policy

`src/core/model-routing.js` routes by task properties, not vendor name. A separate benchmark snapshot maps the abstract tier to currently strong models. This prevents a leaderboard update from changing deterministic PARA11AX logic.

Base routing:

| Task class | Default tier | Reasoning | Review |
| --- | --- | --- | --- |
| simple transform / formatting | economy | low | no |
| routine research / analysis | balanced | medium | risk-dependent |
| coding / debugging | frontier | high | for high risk or repeated failure |
| security analysis | frontier | high | different-family reviewer when high risk |
| long-context synthesis | frontier | high | risk-dependent |
| deep reasoning | frontier_max | max | independent |
| explicit review | frontier | high | different family |

Escalation:

- zero failures: use the base route;
- one material failure: minimum frontier/high;
- two or more material failures: frontier_max/max plus independent different-family review;
- high-risk tasks can never be cost-demoted below frontier/high and require independent review;
- a reviewer should not share the primary model family when an alternative is available, reducing correlated failure modes.

Cost sensitivity only demotes low-risk, low-complexity work. Latency sensitivity only lowers effort on low-risk work. Model capability is not sacrificed to save pennies on tasks where a wrong answer is expensive.

## 4. Model snapshot: 2026-09-13

This table is advisory host configuration. Re-evaluate it whenever a major model or benchmark version changes.

| Workload | Preferred model / mode | Why |
| --- | --- | --- |
| cheap extraction, normalization, formatting, bulk low-risk transforms | GPT-5.6 Luna | OpenAI positions Luna for cost-sensitive high-volume work. Do not spend frontier reasoning tokens on deterministic clerical work. |
| default complex research, CTI synthesis, general professional analysis | GPT-5.6 Sol medium/high | OpenAI's default flagship recommendation for complex reasoning/coding, 1.05M context, substantially cheaper than current top-end Astra. Escalate only when the task warrants it. |
| hard coding, repo-wide debugging, difficult agentic implementation | GPT-6 Astra high/max | Artificial Analysis Coding Agent Index v4.3 places Astra max at 62, tied for first, ahead of GPT-5.6 Sol at 55; Astra also used materially fewer tokens per task in that harness. |
| deepest reasoning or repeated-failure escalation | GPT-6 Astra max | Tied for first on Artificial Analysis Intelligence Index v4.3. Use only when the expected quality gain justifies its higher price and latency. |
| independent high-stakes reviewer | Claude Fable 5.1 high/max | Current independent benchmark leader/tie from a different model family. Different-family review is for error diversity, not because any benchmark proves independence. |
| low-risk second pass / critique | strongest economical non-primary-family model meeting context needs | Diversity matters more than paying max effort for a routine critique. |

Current evidence:

- OpenAI model selection and GPT-5.6 family: https://platform.openai.com/docs/models
- Artificial Analysis, GPT-6 Astra: https://artificialanalysis.ai/articles/benchmarking-gpt-6-astra
- Artificial Analysis Intelligence Index v4.3: https://artificialanalysis.ai/articles/artificial-analysis-intelligence-index-v4-3
- Artificial Analysis coding-agent comparison: https://artificialanalysis.ai/agents/coding-agents/comparisons/claude-code-vs-codex
- Artificial Analysis, Claude Fable 5.1: https://artificialanalysis.ai/articles/claude-fable-5-1
- ARC Prize technical analysis of GPT-6 Astra: use the current ARC Prize GPT-6 Astra evaluation when validating reasoning/harness behavior.

Benchmark caution: model results depend on harness, tool access, effort level, and benchmark version. ARC-AGI-3 results for GPT-6 Astra vary sharply across tool/harness configurations, so the harness is part of the evaluated system. Never copy a leaderboard ordering into a permanent router without recording its date and evaluation setup.

## 5. Benchmark refresh procedure

Refresh the advisory model mapping when any of these occurs:

- a new frontier model is released;
- Artificial Analysis changes its Intelligence or Coding Agent Index version;
- a materially better task-specific benchmark becomes available;
- provider pricing changes enough to alter the Pareto frontier;
- internal PARA11AX evals contradict the public ranking.

For each candidate, record:

- model and effort level;
- model family;
- context window;
- task-relevant benchmark score;
- token use per task when available;
- cost per task when available;
- latency when material;
- harness/tool configuration;
- snapshot date.

Then feed normalized task-specific scores to `rankModelCandidates()`. The generic router remains unchanged unless the routing policy itself changes.

## 6. Internal evaluation beats generic leaderboard worship

Public benchmarks are priors. PARA11AX should eventually maintain a small frozen eval corpus covering:

- CTI article-to-structured-intelligence extraction;
- provenance correctness and unsupported-claim rate;
- IOC/IOA/TTP distinction;
- ATT&CK mapping precision;
- KQL validity against supported schemas;
- evidence preservation through handoff/context reset;
- instruction and constraint retention after long tool traces;
- code-change correctness on representative repo tasks;
- token and cost per successful task.

Route changes should prefer statistically meaningful improvement on these internal tasks over a generic benchmark lead. A model being excellent at a public coding suite does not magically make it the best analyst for CTI, because apparently benchmarks have not yet abolished specialization.

## 7. Completion gate

A long-running task is complete only when:

1. the canonical objective is satisfied;
2. no required next action remains;
3. invariant hash and state import validate;
4. referenced artifacts exist and are retrievable;
5. task-specific tests or factual verification have been rerun on the final state;
6. high-risk work has passed its required independent review;
7. the final report distinguishes verified evidence from inference and names residual limitations.

For repository changes, the authoritative completion signal is the exact-head CI/status result, not an earlier run and not the agent's recollection of one.
