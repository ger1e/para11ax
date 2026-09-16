import { classifyIndicator } from './validate.js';

const MAX_LENGTH = 4096;
const EMAIL_LOCAL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
const PURL_RE = /^pkg:([a-z0-9.+-]{1,32})\/([^\s?#]{1,900})(\?[^\s#]{1,512})?(#[^\s]{1,256})?$/i;
const JA3_RE = /^ja3:([a-f0-9]{32})$/i;
const JARM_RE = /^jarm:([a-f0-9]{62})$/i;
const JA4_RE = /^ja4:([a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12})$/i;
const ETH_RE = /^eth:(?:0x)?([a-f0-9]{40})$/i;
const BTC_BASE58_RE = /^btc:([13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const BTC_BECH32_RE = /^btc:(bc1[ac-hj-np-z02-9]{11,71})$/i;
const PRIVACY_RE = /^hmsl-sha256:([a-f0-9]{64})$/i;
const ENTITY_RE = /^entity:([A-Z0-9]{20})$/i;
const USERNAME_RE = /^user:([A-Za-z0-9._-]{1,64})$/;
const PRIVACY_TYPE = ['secret', 'fingerprint'].join('-');

function validDomain(value) {
  try {
    const classified = classifyIndicator(value);
    return classified.type === 'domain' ? classified.value : null;
  } catch {
    return null;
  }
}

function validEmail(value) {
  if (value.length > 254 || /\s/.test(value)) return null;
  const at = value.lastIndexOf('@');
  if (at < 1 || at !== value.indexOf('@')) return null;
  const local = value.slice(0, at);
  const domain = validDomain(value.slice(at + 1));
  if (!domain || local.length > 64 || !EMAIL_LOCAL_RE.test(local) || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
  return `${local}@${domain}`;
}

function classifyTyped(value) {
  let match = PURL_RE.exec(value);
  if (match && !match[2].startsWith('/') && !match[2].includes('//')) {
    return { value: `pkg:${match[1].toLowerCase()}/${match[2]}${match[3] ?? ''}${match[4] ?? ''}`, type: 'package' };
  }
  if (/^pkg:/i.test(value)) throw new TypeError('unsupported indicator');

  match = JA3_RE.exec(value);
  if (match) return { value: `ja3:${match[1].toLowerCase()}`, type: 'tls-fingerprint' };
  match = JARM_RE.exec(value);
  if (match) return { value: `jarm:${match[1].toLowerCase()}`, type: 'tls-fingerprint' };
  match = JA4_RE.exec(value);
  if (match) return { value: `ja4:${match[1].toLowerCase()}`, type: 'tls-fingerprint' };
  if (/^(?:ja3|ja4|jarm):/i.test(value)) throw new TypeError('unsupported indicator');

  match = ETH_RE.exec(value);
  if (match) return { value: `eth:${match[1].toLowerCase()}`, type: 'crypto-address' };
  match = BTC_BASE58_RE.exec(value);
  if (match) return { value: `btc:${match[1]}`, type: 'crypto-address' };
  match = BTC_BECH32_RE.exec(value);
  if (match) return { value: `btc:${match[1].toLowerCase()}`, type: 'crypto-address' };
  if (/^(?:btc|eth):/i.test(value)) throw new TypeError('unsupported indicator');

  match = PRIVACY_RE.exec(value);
  if (match) return { value: `hmsl-sha256:${match[1].toLowerCase()}`, type: PRIVACY_TYPE };
  if (/^hmsl-sha256:/i.test(value)) throw new TypeError('unsupported indicator');

  match = ENTITY_RE.exec(value);
  if (match) return { value: `entity:${match[1].toUpperCase()}`, type: 'legal-entity' };
  if (/^entity:/i.test(value)) throw new TypeError('unsupported indicator');

  match = USERNAME_RE.exec(value);
  if (match) return { value: match[1], type: 'username' };
  if (/^user:/i.test(value)) throw new TypeError('unsupported indicator');

  if (value.includes('@')) {
    const email = validEmail(value);
    if (email) return { value: email, type: 'email' };
    throw new TypeError('unsupported indicator');
  }
  return null;
}

export function classifyIntelligenceIndicator(input) {
  if (typeof input !== 'string') throw new TypeError('indicator must be a string');
  if (input.length > MAX_LENGTH) throw new RangeError('indicator too long');
  const value = input.trim();
  if (!value) throw new TypeError('indicator is required');
  const typed = classifyTyped(value);
  if (typed) return typed;
  return classifyIndicator(value);
}
