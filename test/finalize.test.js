import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const finalizePath = new URL('../scripts/finalize.ps1', import.meta.url);
const workflowPath = new URL('../.github/workflows/tooling-smoke.yml', import.meta.url);
const verifyRepoPath = new URL('../scripts/verify-repo.sh', import.meta.url);

function read(path) {
  return readFileSync(path, 'utf8');
}

test('finalizer pins main and applies the required public branch-protection contract', () => {
  const source = read(finalizePath);

  assert.match(source, /RequiredBranch\s*=\s*'main'/);
  assert.match(source, /branches\/\$RequiredBranch\/protection/);
  assert.match(source, /Assert-PublicRepository/);
  assert.match(source, /Tooling smoke/);
  assert.match(source, /required_pull_request_reviews/);
  assert.match(source, /required_status_checks/);
  assert.match(source, /enforce_admins/);
  assert.match(source, /required_linear_history/);
  assert.match(source, /required_conversation_resolution/);
  assert.match(source, /allow_force_pushes/);
  assert.match(source, /allow_deletions/);
  assert.match(source, /status --porcelain/);
  assert.match(source, /fetch[^\r\n]*origin[^\r\n]*main/);
  assert.match(source, /rev-parse[^\r\n]*(FETCH_HEAD|origin\/main)/);
  assert.match(source, /bootstrap-vercel\.ps1/);
});

test('finalizer requires authoritative Tooling smoke success for the exact main SHA before protection and deployment', () => {
  const source = read(finalizePath);

  assert.match(source, /function Assert-ToolingSmokeSuccess/);
  assert.match(source, /commits\/\$Commit\/status/);
  assert.match(source, /\.context -eq \$RequiredStatus/);
  assert.match(source, /\.state -ne 'success'/);
  assert.match(source, /Assert-ToolingSmokeSuccess -Gh \$gh -Commit \$commit/);

  const statusIndex = source.indexOf('Assert-ToolingSmokeSuccess -Gh $gh -Commit $commit');
  const protectIndex = source.indexOf('Set-MainProtection -Gh $gh');
  const deployIndex = source.indexOf('& $BootstrapPath');
  assert.ok(statusIndex >= 0 && protectIndex > statusIndex && deployIndex > protectIndex);
});

test('finalizer reads branch protection back and fails closed on unsafe source state', () => {
  const source = read(finalizePath);

  assert.match(source, /Assert-MainProtection/);
  assert.match(source, /ConvertFrom-Json/);
  assert.match(source, /required_status_checks/);
  assert.match(source, /required_pull_request_reviews/);
  assert.match(source, /Unexpected origin|approved repository/i);
  assert.match(source, /modified or untracked|dirty/i);
  assert.match(source, /current origin\/main|stale/i);
  assert.match(source, /auth status/);
  assert.match(source, /GitHub CLI|gh\.exe|gh command/i);
});

test('Tooling smoke parses the finalizer and repository invariants require its dynamic main-protection contract', () => {
  const workflow = read(workflowPath);
  const verifyRepo = read(verifyRepoPath);

  assert.match(workflow, /'scripts\/finalize\.ps1'/);
  assert.match(verifyRepo, /RequiredBranch.*main/);
  assert.match(verifyRepo, /branches\/\\\$RequiredBranch\/protection/);
  assert.match(verifyRepo, /Tooling smoke/);
});

test('Tooling smoke gates PRs and attests exact merged main while remaining bounded and manual-capable', () => {
  const workflow = read(workflowPath);
  const runnerLines = workflow.match(/^\s+runs-on:/gm) ?? [];

  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /^\s+pull_request:\s*$/m);
  assert.match(workflow, /pull_request:\s*\n\s+branches:\s*\n\s+- main/);
  assert.match(workflow, /^\s+push:\s*$/m);
  assert.match(workflow, /push:\s*\n\s+branches:\s*\n\s+- main/);
  assert.match(workflow, /cancel-in-progress: true/);
  assert.equal(runnerLines.length, 2);
  assert.equal((workflow.match(/runs-on: ubuntu-latest/g) ?? []).length, 2);
  assert.doesNotMatch(workflow, /runs-on: macos-latest/);
  assert.doesNotMatch(workflow, /runs-on: windows-latest/);
  assert.doesNotMatch(workflow, /^\s+schedule:/m);
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /apt-get/);
});

test('Tooling smoke isolates write permission from all checked-out PR code', () => {
  const workflow = read(workflowPath);
  const marker = '\n  publish_status:\n';
  const splitAt = workflow.indexOf(marker);
  assert.ok(splitAt > 0, 'privileged publisher job must exist');

  const validation = workflow.slice(0, splitAt);
  const publisher = workflow.slice(splitAt);

  assert.match(validation, /permissions:\s*\n\s+contents: read/);
  assert.doesNotMatch(validation, /statuses: write/);
  assert.doesNotMatch(validation, /GH_TOKEN:/);
  assert.match(validation, /uses: actions\/checkout@/);
  assert.match(validation, /npm run check/);

  assert.match(publisher, /needs: validate/);
  assert.match(publisher, /if: \$\{\{ always\(\) \}\}/);
  assert.match(publisher, /permissions:\s*\n\s+contents: read\s*\n\s+statuses: write/);
  assert.match(publisher, /STATUS_SHA: \$\{\{ github\.event_name == 'pull_request' && github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  assert.match(publisher, /VALIDATION_RESULT: \$\{\{ needs\.validate\.result \}\}/);
  assert.match(publisher, /statuses\/\$\{STATUS_SHA\}/);
  assert.doesNotMatch(publisher, /actions\/checkout/);
  assert.doesNotMatch(publisher, /npm\s/);
  assert.doesNotMatch(publisher, /scripts\//);
  assert.equal((workflow.match(/statuses: write/g) ?? []).length, 1);
});
