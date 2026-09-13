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

export function classifyIndicator(input) {
  if (typeof input !== 'string') throw new TypeError('indicator must be a string');
  if (input.length > MAX_INDICATOR_LENGTH) throw new RangeError('indicator too long');
  const value = input.trim(); if (!value) throw new TypeError('indicator is required');
  if (net.isIP(value)) return { value, type: 'ip' };
  const cidr = parseCanonicalCidr(value); if (cidr) return { value: cidr.cidr, type: 'cidr' };
  const asn = validAsn(value); if (asn) return { value: asn, type: 'asn' };
  if (/^AS/i.test(value)) throw new TypeError('unsupported indicator');
  if (value.includes('/') && !/^https?:\/\//i.test(value)) throw new TypeError('unsupported indicator');
  if (CVE_RE.test(value)) return { value: value.toUpperCase(), type: 'cve' };
  if (ATTACK_RE.test(value)) return { value: value.toUpperCase(), type: 'attack' };
  const certificate = CERT_SHA256_RE.exec(value);
  if (certificate) return { value: `cert-sha256:${certificate[1].toLowerCase()}`, type: 'certificate' };
  if (/^cert-sha256:/i.test(value)) throw new TypeError('unsupported indicator');
  if (HASH_RE.test(value)) return { value: value.toLowerCase(), type: 'hash' };
  const url = validUrl(value); if (url) return { value: url, type: 'url' };
  const domain = validDomain(value); if (domain) return { value: domain, type: 'domain' };
  throw new TypeError('unsupported indicator');
}
