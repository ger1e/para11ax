const EXECUTION_AUTHORIZATION = Symbol('para11ax.provider-execution-authorization');

function canonicalSubject(subject) {
  if (!subject || typeof subject.type !== 'string' || typeof subject.value !== 'string') return null;
  return `${subject.type}:${subject.value}`;
}

export function createProviderExecutionAuthorization({ adapter, subject } = {}) {
  if (!adapter || typeof adapter.name !== 'string' || !adapter.name) throw new TypeError('adapter is required');
  const canonical = canonicalSubject(subject);
  if (!canonical) throw new TypeError('canonical subject is required');
  return Object.freeze({
    [EXECUTION_AUTHORIZATION]: true,
    provider: adapter.name,
    subject: canonical,
  });
}

export function hasProviderExecutionAuthorization(proof, adapter, subject) {
  const canonical = canonicalSubject(subject);
  return Boolean(
    proof
    && proof[EXECUTION_AUTHORIZATION] === true
    && adapter
    && proof.provider === adapter.name
    && canonical
    && proof.subject === canonical
  );
}
