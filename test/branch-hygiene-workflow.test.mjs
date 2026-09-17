import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflow = await readFile(new URL('../.github/workflows/branch-hygiene.yml', import.meta.url), 'utf8');

test('archive-collapse resolves the current archive tip before deleting captured branches', () => {
  assert.doesNotMatch(workflow, /ARCHIVE_COMMIT:\s*[0-9a-f]{40}/);
  assert.match(workflow, /archive_commit=.*git\/ref\/heads\/\$ARCHIVE_BRANCH/);
  assert.match(workflow, /commits\/\$archive_commit.*\.parents\[\]\.sha/);
  assert.match(workflow, /current_sha.*original_sha/);
});
