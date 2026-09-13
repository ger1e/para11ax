import { COMMAND_REGISTRY } from './catalog.js';

const SPECIAL_DYNAMIC = Object.freeze({
  'provider run': 'providerNames',
});
const LEGACY_CASE_SUBCOMMANDS = Object.freeze(['close', 'export', 'find', 'import', 'list', 'new', 'open', 'refresh', 'show']);

function splitInput(input) {
  const value = String(input ?? '');
  const trailingSpace = /\s$/.test(value);
  const tokens = value.trim().split(/\s+/).filter(Boolean);
  return { tokens, trailingSpace };
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function canonicalAndAliasSequences(surface) {
  const sequences = [];
  for (const descriptor of COMMAND_REGISTRY.forSurface(surface)) {
    sequences.push(descriptor.tokens);
    for (const alias of descriptor.aliases) sequences.push(alias);
  }
  return sequences;
}

function childCompletions(prefixTokens, fragment, surface) {
  const values = [];
  for (const sequence of canonicalAndAliasSequences(surface)) {
    if (sequence.length <= prefixTokens.length) continue;
    let matches = true;
    for (let index = 0; index < prefixTokens.length; index += 1) {
      if (sequence[index] !== prefixTokens[index].toLowerCase()) { matches = false; break; }
    }
    if (!matches) continue;
    const candidate = sequence[prefixTokens.length];
    if (candidate.startsWith(fragment.toLowerCase())) values.push(candidate);
  }
  return uniqueSorted(values);
}

function resolveDescriptor(tokens, surface) {
  const resolved = COMMAND_REGISTRY.resolve(tokens, surface);
  if (!resolved || !resolved.surfaceAvailable) return null;
  return resolved;
}

function legacyCaseCompletions(tokens, trailingSpace, caseTypes) {
  if (!caseTypes.length) return null;
  const root = tokens[0]?.toLowerCase();

  if (root === 'unpin') {
    if (tokens.length === 1 && trailingSpace) return uniqueSorted(caseTypes);
    if (tokens.length === 2 && !trailingSpace) {
      return uniqueSorted(caseTypes).filter(value => value.toLowerCase().startsWith(tokens[1].toLowerCase()));
    }
    return tokens.length > 1 ? [] : null;
  }

  if (root !== 'case') return null;
  if (tokens.length === 1) return trailingSpace ? [...LEGACY_CASE_SUBCOMMANDS] : null;

  const subcommand = tokens[1].toLowerCase();
  if (tokens.length === 2 && !trailingSpace) {
    return LEGACY_CASE_SUBCOMMANDS.filter(value => value.startsWith(subcommand));
  }
  if (subcommand !== 'find') return [];
  if (tokens.length === 2 && trailingSpace) return uniqueSorted(caseTypes);
  if (tokens.length === 3 && !trailingSpace) {
    return uniqueSorted(caseTypes).filter(value => value.toLowerCase().startsWith(tokens[2].toLowerCase()));
  }
  return [];
}

export function completeShellInput(input, {
  surface = 'web',
  providerNames = [],
  observableTypes = [],
  caseTypes = [],
} = {}) {
  const { tokens, trailingSpace } = splitInput(input);

  if (!tokens.length) {
    return childCompletions([], '', surface);
  }

  if (!trailingSpace && tokens.length === 1) {
    return childCompletions([], tokens[0], surface);
  }

  const legacyCase = legacyCaseCompletions(tokens, trailingSpace, caseTypes);
  if (legacyCase !== null) return legacyCase;

  const prefixTokens = trailingSpace ? tokens : tokens.slice(0, -1);
  const fragment = trailingSpace ? '' : tokens[tokens.length - 1];
  const children = childCompletions(prefixTokens, fragment, surface);
  if (children.length) return children;

  const resolved = resolveDescriptor(prefixTokens, surface) ?? resolveDescriptor(tokens, surface);
  if (!resolved) return [];

  const descriptor = resolved.descriptor;
  const commandKey = descriptor.tokens.join(' ');
  const argumentIndex = trailingSpace
    ? tokens.length - descriptor.tokens.length
    : Math.max(0, tokens.length - descriptor.tokens.length - 1);

  if (SPECIAL_DYNAMIC[commandKey] === 'providerNames' && argumentIndex === 0) {
    return uniqueSorted(providerNames).filter(value => value.toLowerCase().startsWith(fragment.toLowerCase()));
  }

  if (descriptor.id === 'case.find' && argumentIndex === 0) {
    return uniqueSorted(caseTypes).filter(value => value.toLowerCase().startsWith(fragment.toLowerCase()));
  }

  if (descriptor.completion?.values && argumentIndex === 0) {
    return uniqueSorted(descriptor.completion.values)
      .filter(value => value.toLowerCase().startsWith(fragment.toLowerCase()));
  }

  if (descriptor.id === 'intel.intel' && argumentIndex === 0 && observableTypes.length) {
    return uniqueSorted(observableTypes).filter(value => value.toLowerCase().startsWith(fragment.toLowerCase()));
  }

  return [];
}
