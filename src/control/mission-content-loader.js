import { readFile as nodeReadFile } from 'node:fs/promises';

import { ShellCommandError, shellError } from '../../app/shell-core/errors.js';

const MAX_BYTES = 2 * 1024 * 1024;
const KINDS = new Set([
  'profile', 'context', 'hunt', 'result', 'workspace',
  'domain-enrichment', 'domain-surface', 'domain-vulnerability',
]);

function deny(message) {
  throw shellError('POLICY_DENIED', message);
}

function boundedText(value) {
  if (typeof value !== 'string') throw shellError('INVALID_ARGUMENT', 'mission content must be UTF-8 text');
  if (new TextEncoder().encode(value).byteLength > MAX_BYTES) throw shellError('OUTPUT_LIMIT', 'mission content exceeds 2 MiB');
  return value;
}

export function createMissionContentLoader({
  readFile = nodeReadFile,
  stdinContent = null,
} = {}) {
  if (typeof readFile !== 'function') throw new TypeError('mission readFile function required');

  return async function loadMissionContent({ kind, args = [] } = {}) {
    if (!KINDS.has(kind)) deny('unsupported mission content kind');
    if (!Array.isArray(args)) deny('mission transport arguments must be an array');

    if (args.length === 1 && args[0] === '--stdin') {
      if (typeof stdinContent !== 'string') deny('mission stdin content unavailable');
      return boundedText(stdinContent);
    }

    if (args.length === 2 && args[0] === '--file') {
      const path = args[1];
      if (typeof path !== 'string' || !path.trim() || path.startsWith('--')) deny('mission --file requires one path');
      try {
        return boundedText(await readFile(path, 'utf8'));
      } catch (error) {
        if (error instanceof ShellCommandError) throw error;
        throw shellError('INVALID_ARGUMENT', 'mission file could not be read');
      }
    }

    deny('mission content requires exactly one --file <path> or --stdin transport');
  };
}
