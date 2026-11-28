import test from 'node:test';
import assert from 'node:assert/strict';
import { virustotalProvider } from '../src/providers/virustotal.js';

const input = { type: 'ip', value: '192.0.2.44' };
const response = (data, status = 200) => new Response(JSON.stringify(data), { status });
const base = { data: { id: input.value, attributes: { last_analysis_stats: { malicious: 2, harmless: 20 }, asn: 64500, country: 'ZZ' } } };

test('community lookup is opt-in, with point report and direct portal link retained', async () => {
  let count = 0;
  const result = await virustotalProvider.run(input, {
    env: { VIRUSTOTAL_API_KEY: 'test-key' },
    fetchImpl: async () => { count++; return response(base); },
  });
  assert.equal(count, 1);
  assert.equal(result.attributes.community.status, 'disabled');
  assert.equal(result.attributes.asn, 64500);
  assert.deepEqual(result.references, ['https://www.virustotal.com/gui/ip-address/192.0.2.44']);
});

test('community ranking is bounded, excludes abuse and defangs links without changing verdict', async () => {
  let count = 0;
  const comment = (text, positive, negative = 0, abuse = 0) => ({ type: 'comment', attributes: { text, votes: { positive, negative, abuse }, date: 1700000000 } });
  const result = await virustotalProvider.run(input, {
    env: { VIRUSTOTAL_API_KEY: 'test-key', VIRUSTOTAL_COMMUNITY_COMMENTS: 'true' },
    fetchImpl: async url => {
      count++;
      if (!String(url).includes('/comments?')) return response(base);
      return response({ data: [comment('noisy', 10, 9), comment('reported context https://example.com', 8, 1), comment('abuse', 100, 0, 1)], links: { next: 'ignored' } });
    },
  });
  assert.equal(count, 2);
  assert.equal(result.attributes.community.topComment, 'reported context hxxps://example.com');
  assert.equal(result.attributes.community.status, 'reported_unverified');
  assert.equal(result.attributes.community.morePages, true);
  assert.equal(result.malwareFamily, undefined);
  assert.deepEqual(result.attributes.lastAnalysisStats, base.data.attributes.last_analysis_stats);
});

test('community rate limit leaves point evidence intact', async () => {
  const result = await virustotalProvider.run(input, {
    env: { VIRUSTOTAL_API_KEY: 'test-key', VIRUSTOTAL_COMMUNITY_COMMENTS: 'true' },
    fetchImpl: async url => String(url).includes('/comments?') ? response({}, 429) : response(base),
  });
  assert.equal(result.attributes.community.status, 'http_429');
  assert.deepEqual(result.attributes.lastAnalysisStats, base.data.attributes.last_analysis_stats);
});
