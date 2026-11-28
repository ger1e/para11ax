import test from 'node:test';
import assert from 'node:assert/strict';
import { threatfoxProvider } from '../src/providers/threatfox.js';
import { otxProvider } from '../src/providers/otx.js';
import { abuseipdbProvider } from '../src/providers/abuseipdb.js';

const input = {type:'ip', value:'192.0.2.44'};
const response = value => new Response(JSON.stringify(value), {status:200});

test('ThreatFox preserves multiple labels without selecting one as attribution', async () => {
  const rows = [{id:'123', malware_printable:'Family A', confidence_level:80},
    {id:'124', malware_printable:'Family B', confidence_level:50}];
  const result = await threatfoxProvider.run(input, {env:{ABUSECH_API_KEY:'test-key'},fetchImpl:async()=>response({query_status:'ok',data:rows})});
  assert.equal(result.malwareFamily,null);
  assert.equal(result.confidence,null);
  assert.equal(result.attributes.conflictingFamilyLabels,true);
  assert.deepEqual(result.attributes.reportedMalwareFamilies,['Family A','Family B']);
  assert.ok(result.references.includes('https://threatfox.abuse.ch/ioc/123/'));
});

test('OTX retains pulse descriptions as reported community context', async () => {
  const id = 'a'.repeat(24);
  const result = await otxProvider.run(input,{env:{OTX_API_KEY:'test-key'},fetchImpl:async()=>response({
    pulse_info:{count:1,pulses:[{id,name:'Example pulse',description:'Example description',
      adversary:'Reported actor',malware_families:[{name:'Family A'}]}]}
  })});
  assert.equal(result.attributes.communityPulseRecords[0].description,'Example description');
  assert.deepEqual(result.attributes.communityReportedAdversaries,['Reported actor']);
  assert.deepEqual(result.attributes.communityReportedMalwareFamilies,['Family A']);
  assert.ok(result.references.includes('https://otx.alienvault.com/pulse/'+id));
});

test('AbuseIPDB verbose reports preserve counts, sanitize comments and omit reporter identity', async () => {
  let requested;
  const result = await abuseipdbProvider.run(input,{env:{ABUSEIPDB_API_KEY:'test-key'},fetchImpl:async url=>{
    requested=String(url);
    return response({data:{abuseConfidenceScore:81,totalReports:2,numDistinctUsers:2,reports:[
      {reportedAt:'2026-11-27T00:00:00Z',categories:[14,14,18],comment:'token=secret-value',reporterId:4},
      {reportedAt:'2026-11-26T00:00:00Z',categories:[14],comment:'Example report'}]}});
  }});
  assert.ok(requested.includes('verbose'));
  assert.equal(result.attributes.communityReturnedReportCount,2);
  assert.deepEqual(result.attributes.communityCategoryCounts,[{category:14,count:2},{category:18,count:1}]);
  assert.equal(result.attributes.communityRecentReports[0].comment,'[REDACTED]');
  assert.ok(!JSON.stringify(result).includes('reporterId'));
  assert.equal(result.verdict,'malicious');
});
