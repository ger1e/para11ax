# MCP Investigation Import Transport Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore authenticated MCP round-trip import for every valid Investigation v2 bundle while preserving the existing 128 KiB public/discovery request ceiling.

**Architecture:** Keep 128 KiB as the default MCP body bound. Verify bearer/OAuth from headers before selecting a larger parser ceiling, derive that ceiling from the existing 4 MiB Investigation v2 bundle contract, and accept oversized authenticated bodies only when the parsed request is exactly `tools/call` -> `para11ax_investigation` -> `operation: import`; all other oversized calls remain rejected.

**Tech Stack:** Node.js 24, built-in `node:test`, JSON-RPC MCP transport, PARA11AX Investigation v2.

**Spec:** Production smoke on main `dda22b95454dffc1448f59c68b7fc02ebc3216d0` fails only at `INV_ERROR=investigation_import_transport`; `INVESTIGATION_LIMITS.bundleBytes` is 4 MiB while MCP `MAX_BODY_BYTES` is 128 KiB.

## Global Constraints

- Keep public/discovery MCP request ceiling at 128 KiB.
- Do not persist credentials or investigation state server-side.
- Do not expose raw payloads, evidence, tokens, or arbitrary exception text in diagnostics.
- Keep Investigation v2 `bundleBytes` at 4 MiB; transport must honor the domain contract.
- No new npm dependencies.

---

### Task 1: Reproduce the contract mismatch

**Files:**
- Create: `test/mcp-investigation-import-limit.test.js`

**Interfaces:**
- Consumes: `createMcpHttpHandler`, `MCP_PROTOCOL_VERSION`, `createInvestigation`, `reduceInvestigation`, `exportInvestigation`.
- Produces: regression proving a valid >128 KiB Investigation v2 export can be imported over authenticated MCP.

- [ ] **Step 1: Write the failing test**

Create a valid Investigation v2 state with enough bounded notes to exceed 128 KiB, export it canonically, then POST it through `tools/call` / `para11ax_investigation` / `import` with a valid bearer. Assert HTTP 200, `isError === false`, and canonical state round-trips.

- [ ] **Step 2: Verify RED**

Run the new test in CI. Expected failure before the fix: HTTP 413 / JSON-RPC payload-too-large instead of a successful tool result.

### Task 2: Align authenticated transport with Investigation v2 bounds

**Files:**
- Modify: `src/mcp/server.js`
- Test: `test/mcp-investigation-import-limit.test.js`

**Interfaces:**
- Consumes: `INVESTIGATION_LIMITS.bundleBytes`, existing header-only `verifyMcpAuthorization`.
- Produces: bounded authenticated import envelope support; all non-import oversized MCP requests remain rejected.

- [ ] **Step 1: Implement the minimal fix**

Import `INVESTIGATION_LIMITS`; keep the 128 KiB default. Derive an authenticated Investigation import envelope ceiling as `2 * bundleBytes + 64 KiB` to account for JSON string escaping plus RPC envelope. Verify authorization before body parsing, parse authenticated requests up to that ceiling, then reject any body above 128 KiB unless it is exactly the Investigation import call.

- [ ] **Step 2: Verify GREEN**

Run the targeted regression, then the full `npm run check`, Maltego tests, shell/Python/PowerShell gates, CodeQL, and GHAS.

### Task 3: Production verification

**Files:**
- No additional production code unless evidence identifies another root cause.

**Interfaces:**
- Consumes: protected-main merge and exact Vercel deployment SHA.
- Produces: authenticated production MCP smoke with 13/13 conformance surfaces passing.

- [ ] **Step 1: Merge only on green exact-head gates**
- [ ] **Step 2: Confirm Vercel READY on the exact merge SHA**
- [ ] **Step 3: Require `PRODUCTION_MCP_SMOKE=PASS`, `GA=pass`, `GA_SURFACES=13`, and zero failed conformance surfaces**
