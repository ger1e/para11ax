import assert from 'node:assert/strict';
import test from 'node:test';

import { COMMAND_DESCRIPTORS, COMMAND_REGISTRY } from '../app/shell-core/catalog.js';
import { completeShellInput } from '../app/shell-core/completion.js';
import { listAliases, renderCommandIndex, renderManual, searchCommands, whichCommand } from '../app/shell-core/help.js';

const resolve = (tokens, surface = 'web') => COMMAND_REGISTRY.resolve(tokens, surface);

test('absolute-max catalog covers every approved namespace', () => {
  const namespaces = new Set(COMMAND_DESCRIPTORS.map(command => command.namespace));
  for (const namespace of ['discovery','session','system','intel','provider','result','case','report','export','terminal','transform']) {
    assert.ok(namespaces.has(namespace), `missing namespace ${namespace}`);
  }
  assert.ok(COMMAND_DESCRIPTORS.length >= 80, 'absolute-max catalog is unexpectedly small');
});

test('legacy shell and CLI spellings resolve through the shared registry', () => {
  const cases = [
    [['?'], 'discovery.help'],
    [['cls'], 'terminal.clear'],
    [['scan'], 'intel.enrich'],
    [['pivot'], 'intel.enrich'],
    [['osint'], 'osint.user-scanner'],
    [['identity'], 'osint.user-scanner'],
    [['ovr'], 'result.summary'],
    [['evd'], 'result.evidence'],
    [['cor'], 'result.correlation'],
    [['rel'], 'result.relationships'],
    [['cov'], 'result.coverage'],
    [['providers'], 'result.providers'],
    [['providers','list'], 'provider.list'],
    [['providers','env-template'], 'provider.env-template'],
    [['providers','probe'], 'provider.probe'],
    [['doctor'], 'system.doctor'],
    [['release','verify'], 'system.release-verify'],
    [['maltego','check'], 'system.maltego-check'],
  ];
  for (const [tokens, id] of cases) assert.equal(resolve(tokens, 'cli')?.descriptor.id ?? resolve(tokens, 'web')?.descriptor.id, id, tokens.join(' '));
});

test('fixed provider front doors carry immutable provider identities', () => {
  const expected = new Map([
    ['vt','virustotal'], ['gn','greynoise'], ['otx','otx'], ['urlscan','urlscan'], ['threatfox','threatfox'],
    ['malwarebazaar','malwarebazaar'], ['rdap','rdap'], ['epss','epss'], ['kev','cisa-kev'], ['nvd','nvd'], ['censys','censys'],
  ]);
  for (const [token, provider] of expected) {
    const descriptor = resolve([token], 'web').descriptor;
    assert.equal(descriptor.handler, 'provider-run');
    assert.equal(descriptor.provider, provider);
    assert.equal(descriptor.egressClass, 'provider');
    assert.equal(descriptor.auth, 'required');
    assert.ok(Object.isFrozen(descriptor));
  }
  const generic = resolve(['provider','run','virustotal','8.8.8.8'], 'web');
  assert.equal(generic.descriptor.id, 'provider.run');
  assert.deepEqual(generic.args, ['virustotal','8.8.8.8']);
  assert.equal(COMMAND_DESCRIPTORS.some(command => command.tokens[0] === 'curl'), false);
});

test('GreyNoise Swarm catalog conservatively declares browser download side effects', () => {
  const descriptor = resolve(['swarm'], 'web').descriptor;
  assert.equal(descriptor.id, 'osint.greynoise-swarm');
  assert.equal(descriptor.sideEffect, 'browser-download');
});

test('surface-specific commands stay out of completion but remain visible in help and man', () => {
  assert.equal(completeShellInput('system set', { surface: 'web' }).includes('setup'), false);
  assert.match(renderCommandIndex(), /system setup.*\[CLI ONLY\]/i);
  assert.match(renderManual('system setup'), /\[CLI ONLY\]/i);
  assert.match(renderManual('sound'), /\[WEB ONLY\]/i);
});

test('completion is generated from command paths and declarative argument metadata', () => {
  assert.deepEqual(completeShellInput('enr', { surface: 'web' }), ['enrich']);
  assert.deepEqual(completeShellInput('auth ', { surface: 'web' }), ['clear','status']);
  assert.deepEqual(completeShellInput('profile f', { surface: 'web' }), ['fast','full']);
  assert.deepEqual(completeShellInput('view c', { surface: 'web' }), ['correlation','coverage']);
  assert.deepEqual(completeShellInput('user-scanner ', { surface: 'web' }), ['email','username']);
  assert.deepEqual(completeShellInput('provider run ', { surface: 'web', providerNames: ['virustotal','greynoise'] }), ['greynoise','virustotal']);
  assert.deepEqual(completeShellInput('intel ', { surface: 'web', observableTypes: ['ip','domain'] }), ['asn','certificate','cidr','cve','domain','hash','ip','url']);
});

test('help discovery functions project the same registry source', () => {
  assert.match(renderCommandIndex(), /provider run <provider> <observable>/i);
  assert.match(renderManual('vt'), /virustotal/i);
  assert.match(whichCommand('scan'), /enrich/i);
  assert.ok(searchCommands('evidence').some(item => item.id === 'result.evidence'));
  assert.ok(listAliases().some(item => item.alias === 'scan' && item.command === 'enrich'));
});
