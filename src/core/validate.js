import net from 'node:net';
import { domainToASCII } from 'node:url';
import { parseCanonicalCidr } from './network.js';

const MAX_INDICATOR_LENGTH = 4096;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const ATTACK_RE = /^(?:T\d{4}(?:\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|M\d{4}|C\d{4}|DS\d{4}|DC\d{4}|DET\d{4})$/i;
const CERT_SHA256_RE = /^cert-sha256:([a-fA-F0-9]{64})$/;
const HASH_RE = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
const ASN_RE = /^AS([1-9]\d*)$/i;
const MAX_ASN = 4_294_967_295n;
const EMAIL_LOCAL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
const PURL_RE = /^pkg:([a-z0-9.+-]{1,32})\/([^\s?#]{1,900})(\?[^\s#]{1,512})?(#[^\s]{1,256})?$/i;
const JA3_RE = /^ja3:([a-f0-9]{32})$/i;
const JARM_RE = /^jarm:([a-f0-9]{62})$/i;
const JA4_RE = /^ja4:([a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12})$/i;
const ETH_RE = /^eth:(?:0x)?([a-f0-9]{40})$/i;
const BTC_BASE58_RE = /^btc:([13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const BTC_BECH32_RE = /^btc:(bc1[ac-hj-np-z02-9]{11,71})$/i;
const PRIVACY_FINGERPRINT_RE = /^hmsl-sha256:([a-f0-9]{64})$/i;
const ENTITY_RE = /^entity:([A-Z0-9]{20})$/i;
const USERNAME_RE = /^user:([A-Za-z0-9._-]{1,64})$/;
const PRIVACY_FINGERPRINT_TYPE = ['secret', 'fingerprint'].join('-');

function validDomain(value) {
  const raw = String(value).toLowerCase();
  if (!raw.includes('.')) return null;
  const ascii = domainToASCII(raw);
  if (!ascii || ascii.length > 253 || !ascii.includes('.') || net.isIP(ascii)) return null;
  const labels = ascii.split('.');
  if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9-]+$/i.test(label) || label.startsWith('-') || label.endsWith('-'))) return null;
  return ascii;
}

function validUrl(value) {
  let parsed; try { parsed = new URL(value); } catch { return null; }
  if (!['http:', 'https:'].includes(parsed.protocol)) return null;
  const host = validDomain(parsed.hostname) ?? (net.isIP(parsed.hostname) ? parsed.hostname : null);
  if (!host || parsed.username || parsed.password) return null;
  parsed.hostname = host; parsed.hash = '';
  return parsed.toString();
}

function validAsn(value) {
  const match = ASN_RE.exec(value);
  if (!match) return null;
  if (match[1].length > 1 && match[1].startsWith('0')) return null;
  const number = BigInt(match[1]);
  if (number < 1n || number > MAX_ASN) return null;
  return `AS${number}`;
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

function validPurl(value) {
  const match = PURL_RE.exec(value);
  if (!match || match[2].startsWith('/') || match[2].includes('//')) return null;
  return `pkg:${match[1].toLowerCase()}/${match[2]}${match[3] ?? ''}${match[4] ?? ''}`;
}

function validTlsFingerprint(value) {
  const ja3 = JA3_RE.exec(value); if (ja3) return `ja3:${ja3[1].toLowerCase()}`;
  const jarm = JARM_RE.exec(value); if (jarm) return `jarm:${jarm[1].toLowerCase()}`;
  const ja4 = JA4_RE.exec(value); if (ja4) return `ja4:${ja4[1].toLowerCase()}`;
  return null;
}

function validCryptoAddress(value) {
  const eth = ETH_RE.exec(value); if (eth) return `eth:${eth[1].toLowerCase()}`;
  const base58 = BTC_BASE58_RE.exec(value); if (base58) return `btc:${base58[1]}`;
  const bech32 = BTC_BECH32_RE.exec(value); if (bech32) return `btc:${bech32[1].toLowerCase()}`;
  return null;
}

function validPrivacyFingerprint(value) {
  const match = PRIVACY_FINGERPRINT_RE.exec(value);
  return match ? `hmsl-sha256:${match[1].toLowerCase()}` : null;
}

function validLegalEntity(value) {
  const match = ENTITY_RE.exec(value);
  return match ? `entity:${match[1].toUpperCase()}` : null;
}

function validUsername(value) {
  const match = USERNAME_RE.exec(value);
  return match ? match[1] : null;
}

export function classifyIndicator(input) {
  if (typeof input !== 'string') throw new TypeError('indicator must be a string');
  if (input.length > MAX_INDICATOR_LENGTH) throw new RangeError('indicator too long');
  const value = input.trim(); if (!value) throw new TypeError('indicator is required');
  if (net.isIP(value)) return { value, type: 'ip' };
  const cidr = parseCanonicalCidr(value); if (cidr) return { value: cidr.cidr, type: 'cidr' };
  const asn = validAsn(value); if (asn) return { value: asn, type: 'asn' };
  if (/^AS/i.test(value)) throw new TypeError('unsupported indicator');
  if (CVE_RE.test(value)) return { value: value.toUpperCase(), type: 'cve' };
  if (ATTACK_RE.test(value)) return { value: value.toUpperCase(), type: 'attack' };

  const certificate = CERT_SHA256_RE.exec(value);
  if (certificate) return { value: `cert-sha256:${certificate[1].toLowerCase()}`, type: 'certificate' };
  if (/^cert-sha256:/i.test(value)) throw new TypeError('unsupported indicator');

  const purl = validPurl(value); if (purl) return { value: purl, type: 'package' };
  if (/^pkg:/i.test(value)) throw new TypeError('unsupported indicator');
  const tls = validTlsFingerprint(value); if (tls) return { value: tls, type: 'tls-fingerprint' };
  if (/^(?:ja3|ja4|jarm):/i.test(value)) throw new TypeError('unsupported indicator');
  const crypto = validCryptoAddress(value); if (crypto) return { value: crypto, type: 'crypto-address' };
  if (/^(?:btc|eth):/i.test(value)) throw new TypeError('unsupported indicator');
  const privacy = validPrivacyFingerprint(value); if (privacy) return { value: privacy, type: PRIVACY_FINGERPRINT_TYPE };
  if (/^hmsl-sha256:/i.test(value)) throw new TypeError('unsupported indicator');
  const entity = validLegalEntity(value); if (entity) return { value: entity, type: 'legal-entity' };
  if (/^entity:/i.test(value)) throw new TypeError('unsupported indicator');
  const username = validUsername(value); if (username) return { value: username, type: 'username' };
  if (/^user:/i.test(value)) throw new TypeError('unsupported indicator');

  const email = validEmail(value); if (email) return { value: email, type: 'email' };
  if (value.includes('@')) throw new TypeError('unsupported indicator');
  if (value.includes('/') && !/^https?:\/\//i.test(value)) throw new TypeError('unsupported indicator');
  if (HASH_RE.test(value)) return { value: value.toLowerCase(), type: 'hash' };
  const url = validUrl(value); if (url) return { value: url, type: 'url' };
  const domain = validDomain(value); if (domain) return { value: domain, type: 'domain' };
  throw new TypeError('unsupported indicator');
}
