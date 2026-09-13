# Durable Agent Handoff Architecture

Date: 2026-09-13
Status: Design review
Target: PARA11AX control plane and MCP workflow surface

## 1. Problem

PARA11AX already favors explicit state-in/state-out workflows over hidden conversational state. Agent-to-agent work needs the same discipline. A worker must not be able to declare a task complete and leave the next agent to reconstruct intent, validation status, artifacts, or failure history from chat transcripts.

The workflow therefore needs a durable, machine-verifiable handoff contract that is written at every task boundary and can be consumed by the next agent without relying on hidden memory.

## 2. Goals

1. Every non-terminal task transition emits one canonical handoff record.
2. A task cannot become handoff-ready until required verification passes.
3. Every handoff identifies the current task, next task, current role, next role, exact next action, relevant artifacts, assumptions, failures, and verification evidence.
4. Failed verification remains visible and drives bounded repair or rollback rather than disappearing into subsequent context.
5. Handoffs are deterministic, auditable, versioned, and safe to replay.
6. Concurrent agents cannot silently claim the same handoff.
7. Context passed forward is compact, while complete provenance remains addressable through artifact references.
8. Existing PARA11AX mission/investigation/case state remains authoritative for domain work. Handoff state coordinates agents around that state rather than replacing it.
9. Repository verification and documentation-drift controls validate the handoff contract.
10. Self-improvement changes can be proposed and evaluated but cannot directly mutate production behavior.

## 3. Non-goals

- Replacing PARA11AX with a generic orchestration engine.
- Persisting chain-of-thought or hidden model reasoning.
- Storing credentials, tokens, secrets, or unrestricted raw customer data in handoff records.
- Allowing arbitrary shell commands embedded in a handoff to execute automatically.
- Allowing an agent to promote its own prompt, policy, model, or code changes directly to production.
- Requiring a new database solely for v1 if the existing state/artifact persistence mechanism can provide durable storage and revision checks.

## 4. Design principles

### Explicit over implicit

The receiving agent should be able to resume from the durable handoff plus referenced artifacts. Chat history is optional context, not a dependency.

### Fail closed

`handoff_ready` is impossible while required verification is pending or failed. Missing mandatory fields invalidate the transition.

### Evidence over self-attestation

The worker records what it changed. A verifier records whether acceptance criteria passed and attaches evidence. For production-impacting or self-improvement changes, worker and verifier identities/roles must be distinct.

### Minimal continuation context

The handoff contains the compressed facts required to continue. Large logs, reports, datasets, and code outputs are referenced as artifacts rather than copied into the record.

### Backward-compatible domain state

Mission, investigation, case, report, and provider state remain separate. A handoff may reference those objects by stable identifiers.

## 5. Proposed component boundaries

### `src/control/agent-handoff.js`

Pure control-plane logic for:

- schema normalization and validation
- legal state transitions
- completion-gate evaluation
- verifier requirements
- retry/rollback decisions
- claim/revision checks
- redaction/safety checks on handoff fields

This module must not execute arbitrary commands from handoff content.

### `src/control/handoff-store.js`

A thin persistence adapter using the repository's existing durable state mechanism where possible. It owns:

- create/read/update of handoff records
- monotonically increasing `revision`
- compare-and-set updates for claiming
- append-only transition/audit history or equivalent immutable transition evidence

Storage implementation is deliberately separated from transition logic so it can change without changing the contract.

### `src/mcp/server.js`

Expose narrow MCP operations rather than generic state mutation. Proposed operations:

- `handoff_prepare`
- `handoff_verify`
- `handoff_claim`
- `handoff_fail`
- `handoff_get`

The MCP layer authenticates/authorizes requests, validates input, calls control-plane functions, and returns the canonical record. It does not duplicate transition rules.

### Verification integration

The repository verification path, including `scripts/verify-repo.sh` and existing tests, gains handoff contract checks. Documentation and schema/version drift become CI failures.

## 6. Handoff v1 contract

The canonical representation is JSON-compatible and versioned.

```json
{
  "schema_version": "1",
  "handoff_id": "hf_...",
  "workflow_id": "wf_...",
  "revision": 3,
  "parent_task_id": "task_...",
  "current_task_id": "task_...",
  "next_task_id": "task_...",
  "status": "handoff_ready",
  "change_class": "standard",
  "current_agent": {
    "id": "agent_...",
    "role": "worker"
  },
  "next_agent": {
    "id": null,
    "role": "worker"
  },
  "objective": "...",
  "summary": "...",
  "changes": [
    {
      "path": "src/...",
      "reason": "..."
    }
  ],
  "artifacts": [
    {
      "kind": "commit",
      "id": "<sha>",
      "uri": "...",
      "digest": null
    }
  ],
  "verification": {
    "required": true,
    "status": "passed",
    "verifier": {
      "id": "agent_...",
      "role": "verifier"
    },
    "checks": [
      {
        "name": "unit-tests",
        "result": "pass",
        "evidence": "artifact-or-run-reference"
      }
    ]
  },
  "assumptions": [],
  "failures": [],
  "rollback": {
    "last_known_good_ref": "<sha-or-state-ref>",
    "action": "..."
  },
  "open_items": [],
  "next_action": "...",
  "claim": {
    "claimed_by": null,
    "claimed_at": null
  },
  "created_at": "2026-09-13T00:00:00Z",
  "updated_at": "2026-09-13T00:00:00Z"
}
```

### Required invariants

- `schema_version`, `handoff_id`, `workflow_id`, `current_task_id`, `status`, `objective`, `summary`, `revision`, and timestamps are always present.
- `revision` is monotonically increasing.
- Every non-terminal state has a non-empty `next_action`.
- `next_task_id` and `next_agent.role` are mandatory before `handoff_ready`.
- `handoff_ready` requires `verification.status == passed` whenever verification is required.
- A failed or blocked record contains at least one failure/reason and a recovery, retry, or rollback `next_action`.
- Only the true terminal `workflow_complete` state may omit `next_action` and `next_task_id`.
- A verifier cannot be the same actor as the worker for `production`, `security_sensitive`, or `self_improvement` change classes.
- Artifact references are data, never executable instructions.
- Secrets and credential-shaped values are rejected or redacted before persistence.

## 7. State machine

Primary path:

```text
working
  -> verification_pending
  -> verified
  -> handoff_ready
  -> claimed
  -> working (next task)
```

Failure path:

```text
verification_pending
  -> verification_failed
  -> repair_pending
  -> working
  -> verification_pending
```

If the retry budget is exhausted:

```text
verification_failed
  -> blocked
  -> rollback_pending | human_review
```

Terminal path:

```text
verified
  -> workflow_complete
```

No transition may skip required verification.

## 8. Claim and concurrency semantics

A handoff is claimed with optimistic concurrency:

1. Receiver reads handoff at revision N.
2. Receiver submits `handoff_claim(handoff_id, expected_revision=N)`.
3. Store performs compare-and-set.
4. Exactly one claimant can advance the record to N+1.
5. Other claimants receive a conflict and must reload canonical state.

This prevents two agents from independently continuing the same task while keeping the implementation simpler than a distributed lock service.

## 9. Verification gates

Verification is part of the contract, not prose in a prompt.

Each task declares acceptance checks. Verification records contain named checks and evidence references. Typical checks include:

- unit/integration tests
- repository verification
- schema validation
- lint/static checks where applicable
- security checks
- production smoke for deployable changes
- documentation consistency
- benchmark/regression checks for self-improvement

A worker can request verification but cannot mark its own required verification as passed for protected change classes.

## 10. Retry and rollback

Each workflow/task policy defines a bounded retry budget. The handoff records every failed attempt rather than overwriting history.

After a verification failure:

- failure reason and evidence are appended
- state becomes `verification_failed`
- next action becomes a concrete repair action
- retry count increments
- once the budget is exhausted, state becomes `blocked`, `rollback_pending`, or `human_review`

Rollback references the last known-good commit/state/artifact. The handoff layer describes the rollback target and intent; execution remains controlled by the appropriate existing subsystem.

## 11. Artifact registry

The handoff carries small typed references to artifacts such as:

- commit
- pull request
- workflow/build run
- report
- dataset
- configuration
- documentation
- test/evaluation result
- mission/investigation/case object

Where an immutable digest is meaningful, the artifact can include one. The registry prevents the receiving agent from guessing which output is canonical.

## 12. Context compression

`summary`, `assumptions`, `open_items`, `changes`, and `next_action` form the continuation packet. Large evidence stays behind references.

The handoff must avoid:

- full chat transcripts
- hidden reasoning
- redundant logs
- duplicated datasets
- credentials or tokens

The receiver is expected to hydrate only the artifacts necessary for its next action.

## 13. Security and trust boundaries

Handoff content is untrusted structured input even when generated by another agent.

Controls:

- strict schema and enum validation
- maximum field/array sizes
- normalized artifact identifiers/paths
- no shell interpolation or automatic execution
- credential/token redaction or rejection
- authorization applied at the MCP boundary
- compare-and-set claim semantics
- append-only transition evidence
- independent verification for protected change classes
- safe failure on unknown schema versions

## 14. Self-improvement guardrail

Changes to prompts, policies, evaluation logic, models, routing, or autonomous behavior use `change_class = self_improvement`.

They require:

1. isolated branch/evaluation context
2. fixed benchmark/evaluation-set identifier
3. recorded baseline result
4. recorded candidate result
5. explicit regression thresholds
6. independent verifier
7. human-controlled promotion into production

The system may propose and test improvements. It may not directly promote its own behavioral changes to production. This converts self-improvement from recursive vibes into an auditable experiment.

## 15. Observability

Emit structured events/counters sufficient to measure:

- handoffs created
- successful claims
- claim conflicts
- verification passes/failures
- retries
- rollbacks
- blocked/human-review transitions
- terminal workflow completions
- handoff validation failures

Derived metrics should include handoff success rate, verifier rejection rate, average retries per task, failure-to-recovery rate, and workflows requiring human intervention.

No metric payload should contain secrets or unrestricted customer evidence.

## 16. Documentation and drift prevention

The handoff schema/version, state machine, MCP operations, and acceptance invariants must have one canonical implementation and matching documentation.

Repository verification should fail when, for example:

- documented schema version differs from implementation
- MCP metadata exposes operations absent from implementation
- required state transitions lack tests
- examples violate the current schema
- a protected change class can self-verify

## 17. Testing strategy

### Unit tests

- valid/invalid schema cases
- every legal state transition
- rejection of illegal transition skips
- required `next_action`
- terminal-state exception
- protected verifier separation
- retry budget handling
- rollback metadata validation
- redaction/secret-shaped input handling

### Concurrency tests

- two claimers on the same revision: exactly one succeeds
- stale revision updates fail
- retry after reload succeeds when legal

### Integration tests

- planner -> worker -> verifier -> handoff -> receiver flow
- failed verification -> repair -> re-verification
- retry exhaustion -> blocked/rollback path
- artifact hydration references remain stable
- MCP operations enforce the same control-plane invariants

### End-to-end acceptance

A fresh receiving agent with no prior chat history can continue a workflow correctly using only:

1. the canonical handoff record
2. the referenced PARA11AX state objects
3. the referenced artifacts

## 18. Acceptance criteria

The feature is ready only when all of the following are true:

- no required-verification task can reach `handoff_ready` without a passed verifier record
- every non-terminal handoff has exactly one canonical next action
- a receiving agent can resume without previous chat context
- two receivers cannot silently claim the same handoff revision
- verification failures remain durable and visible
- retries are bounded
- rollback/human-review escalation exists after exhausted retries
- protected changes cannot self-verify
- handoff data cannot trigger arbitrary command execution
- repository verification includes handoff contract/drift checks
- architecture/operator documentation is updated
- existing mission/investigation/case workflows remain compatible
- all repository tests and verification gates pass

## 19. Rollout

### Phase 1: contract and internal control plane

Implement schema, transition engine, store adapter, tests, and audit events without forcing every existing workflow through the new path.

### Phase 2: MCP surface

Expose prepare/verify/claim/fail/get operations and add conformance tests/tool metadata.

### Phase 3: workflow adoption

Require durable handoff at agent task boundaries. Existing domain-state workflows reference handoff IDs but retain their current canonical state models.

### Phase 4: enforcement

Enable fail-closed completion gating for all agent-driven workflows and add CI/docs drift enforcement.

## 20. Implementation constraint

The implementation should extend existing PARA11AX control-plane and verification conventions rather than create a parallel orchestration stack. If code inspection during implementation reveals an existing canonical persistence or state-transition abstraction, the handoff store/engine should adapt to it rather than duplicate it.
