import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflow = await readFile(new URL('../.github/workflows/release-provenance.yml', import.meta.url), 'utf8');

test('release verification is isolated from publication privileges', () => {
  assert.match(workflow, /jobs:\s*\n\s+verify:\s*\n[\s\S]*?permissions:\s*\n\s+contents: read/);
  assert.match(workflow, /\n\s+attest:\s*\n[\s\S]*?permissions:\s*\n\s+contents: read\s*\n\s+id-token: write\s*\n\s+attestations: write/);
  assert.match(workflow, /\n\s+publish:\s*\n[\s\S]*?permissions:\s*\n\s+contents: write/);
});

test('release artifacts receive GitHub-native provenance attestation with pinned actions', () => {
  assert.match(workflow, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/);
  assert.match(workflow, /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/);
  assert.match(workflow, /actions\/attest@1e69f48acb82d1966a394da916b4c1698aa569d6/);
  assert.match(workflow, /subject-path:\s*\|[\s\S]*release-manifest\.json[\s\S]*sbom\.cdx\.json[\s\S]*sbom\.spdx\.json[\s\S]*build-provenance\.json[\s\S]*SHA256SUMS/);
});

test('release publication fails closed instead of overwriting existing assets', () => {
  assert.doesNotMatch(workflow, /--clobber/);
  assert.match(workflow, /Release \$tag already exists; refusing to overwrite/);
  assert.match(workflow, /if gh release view "\$tag"[^\n]*; then[\s\S]*?exit 1[\s\S]*?fi/);
});
