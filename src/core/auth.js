import { timingSafeEqual } from 'node:crypto';

function readAuthorization(headers) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return headers.get('authorization') ?? '';
  return headers.authorization ?? headers.Authorization ?? '';
}

export function requireGatewayAuth(request, secret) {
  if (typeof secret !== 'string' || secret.length < 1) return false;
  const authorization = readAuthorization(request?.headers);
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(authorization.slice(7), 'utf8');
  const expected = Buffer.from(secret, 'utf8');
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}
