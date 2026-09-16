function parseIpv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some(part => !/^(?:0|[1-9]\d{0,2})$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some(value => value > 255)) return null;
  let value = 0n;
  for (const octet of octets) value = (value << 8n) | BigInt(octet);
  return { version: 4, bits: 32, value };
}

function ipv4ToHexGroups(value) {
  const parts = [];
  for (let shift = 24n; shift >= 0n; shift -= 8n) parts.push(Number((value >> shift) & 255n));
  return [((parts[0] << 8) | parts[1]).toString(16), ((parts[2] << 8) | parts[3]).toString(16)];
}

function parseIpv6(address) {
  let value = address.toLowerCase();
  if (value.includes('%')) return null;
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const v4 = parseIpv4(value.slice(lastColon + 1));
    if (!v4) return null;
    value = `${value.slice(0, lastColon)}:${ipv4ToHexGroups(v4.value).join(':')}`;
  }
  if ((value.match(/::/g) ?? []).length > 1) return null;
  const [leftRaw, rightRaw = ''] = value.split('::');
  const left = leftRaw ? leftRaw.split(':') : [];
  const right = rightRaw ? rightRaw.split(':') : [];
  const valid = part => /^[0-9a-f]{1,4}$/.test(part);
  if (!left.every(valid) || !right.every(valid)) return null;
  if (!value.includes('::') && left.length !== 8) return null;
  if (value.includes('::') && left.length + right.length >= 8) return null;
  const fill = value.includes('::') ? 8 - left.length - right.length : 0;
  const groups = [...left, ...Array(fill).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let numeric = 0n;
  for (const group of groups) numeric = (numeric << 16n) | BigInt(`0x${group}`);
  return { version: 6, bits: 128, value: numeric };
}

export function parseIp(address) {
  if (typeof address !== 'string') return null;
  return parseIpv4(address) ?? parseIpv6(address);
}

function formatIpv4(value) {
  return [24n, 16n, 8n, 0n].map(shift => Number((value >> shift) & 255n)).join('.');
}

function formatIpv6(value) {
  const groups = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(Number((value >> shift) & 0xffffn).toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== '0') { index += 1; continue; }
    let end = index;
    while (end < groups.length && groups[end] === '0') end += 1;
    const length = end - index;
    if (length >= 2 && length > bestLength) { bestStart = index; bestLength = length; }
    index = end;
  }
  if (bestStart < 0) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLength).join(':');
  if (!left && !right) return '::';
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

export function formatIp(parsed) {
  return parsed.version === 4 ? formatIpv4(parsed.value) : formatIpv6(parsed.value);
}

function mask(bits, prefix) {
  if (prefix === 0) return 0n;
  return ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
}

export function parseCanonicalCidr(input) {
  if (typeof input !== 'string' || (input.match(/\//g) ?? []).length !== 1) return null;
  const [address, prefixText] = input.split('/');
  if (!/^(?:0|[1-9]\d*)$/.test(prefixText)) return null;
  const parsed = parseIp(address);
  if (!parsed) return null;
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > parsed.bits) return null;
  const networkValue = parsed.value & mask(parsed.bits, prefix);
  if (networkValue !== parsed.value) return null;
  const canonicalAddress = formatIp({ ...parsed, value: networkValue });
  return Object.freeze({
    version: parsed.version,
    bits: parsed.bits,
    prefix,
    value: networkValue,
    address: canonicalAddress,
    cidr: `${canonicalAddress}/${prefix}`,
  });
}

export function cidrContains(supernet, subnet) {
  const outer = typeof supernet === 'string' ? parseCanonicalCidr(supernet) : supernet;
  const inner = typeof subnet === 'string' ? parseCanonicalCidr(subnet) : subnet;
  if (!outer || !inner || outer.version !== inner.version || outer.prefix > inner.prefix) return false;
  return (inner.value & mask(inner.bits, outer.prefix)) === outer.value;
}

export function cidrOverlaps(a, b) {
  const left = typeof a === 'string' ? parseCanonicalCidr(a) : a;
  const right = typeof b === 'string' ? parseCanonicalCidr(b) : b;
  if (!left || !right || left.version !== right.version) return false;
  return left.prefix <= right.prefix ? cidrContains(left, right) : cidrContains(right, left);
}
