import { createCommandRegistry } from './registry.js';

const BOTH = Object.freeze(['web', 'cli']);
const WEB = Object.freeze(['web']);
const CLI = Object.freeze(['cli']);

function command(id, tokens, namespace, usage, summary, options = {}) {
  return {
    id,
    tokens,
    aliases: options.aliases ?? [],
    namespace,
    surfaces: options.surfaces ?? BOTH,
    auth: options.auth ?? 'none',
    inputTypes: options.inputTypes ?? ['void'],
    outputType: options.outputType ?? 'text',
    egressClass: options.egressClass ?? 'none',
    sideEffect: options.sideEffect ?? 'none',
    capabilities: options.capabilities ?? [],
    handler: options.handler ?? id,
    usage,
    summary,
    ...(options.completion ? { completion: options.completion } : {}),
    ...(options.provider ? { provider: options.provider } : {}),
  };
}

const commands = [
  // Discovery
  command('discovery.help', ['help'], 'discovery', 'help [command]', 'show command index or command help', { aliases: [['?']], handler: 'help' }),
  command('discovery.man', ['man'], 'discovery', 'man <command>', 'show detailed command manual', { handler: 'man' }),
  command('discovery.commands', ['commands'], 'discovery', 'commands [namespace] [--all]', 'list registered commands', { handler: 'commands' }),
  command('discovery.apropos', ['apropos'], 'discovery', 'apropos <term>', 'search command names and descriptions', { handler: 'apropos' }),
  command('discovery.which', ['which'], 'discovery', 'which <command>', 'resolve a command or alias', { handler: 'which' }),
  command('discovery.aliases', ['aliases'], 'discovery', 'aliases', 'list command aliases', { handler: 'aliases', outputType: 'records' }),
  command('discovery.capabilities', ['capabilities'], 'discovery', 'capabilities [type|provider|surface]', 'show shell capability metadata', { handler: 'capabilities', outputType: 'records' }),
  command('discovery.limits', ['limits'], 'discovery', 'limits', 'show shell hard limits', { handler: 'limits', outputType: 'record' }),

  // Session / auth
  command('session.login', ['login'], 'session', 'login', 'open hidden bearer prompt', { surfaces: WEB, sideEffect: 'session', handler: 'login' }),
  command('session.auth-status', ['auth', 'status'], 'session', 'auth status', 'show volatile authentication state', { handler: 'auth-status' }),
  command('session.auth-clear', ['auth', 'clear'], 'session', 'auth clear', 'clear volatile authentication', { sideEffect: 'session', handler: 'auth-clear' }),
  command('session.whoami', ['whoami'], 'session', 'whoami', 'show local session identity and state', { handler: 'whoami' }),
  command('session.session', ['session'], 'session', 'session', 'show current shell session state', { handler: 'session' }),
  command('session.history', ['history'], 'session', 'history', 'show non-secret command history', { handler: 'history' }),
  command('session.history-clear', ['history', 'clear'], 'session', 'history clear', 'clear non-secret command history', { sideEffect: 'session', handler: 'history-clear' }),
  command('session.disconnect', ['disconnect'], 'session', 'disconnect', 'destroy bearer and lock the session', { aliases: [['exit'], ['logout']], sideEffect: 'session', handler: 'disconnect' }),
  command('session.reboot', ['reboot'], 'session', 'reboot', 'replay the PARA11AX boot sequence', { surfaces: WEB, sideEffect: 'session', handler: 'reboot' }),
  command('session.uptime', ['uptime'], 'session', 'uptime', 'show shell uptime', { handler: 'uptime' }),
  command('session.version', ['version'], 'session', 'version', 'show shell and gateway version information', { handler: 'version' }),

  // System / gateway / admin
  command('system.health', ['system', 'health'], 'system', 'system health', 'authenticated gateway health', { aliases: [['health']], auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'health', outputType: 'record' }),
  command('system.status', ['system', 'status'], 'system', 'system status', 'authenticated aggregate runtime status', { aliases: [['status']], auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'status', outputType: 'record' }),
  command('system.meta', ['system', 'meta'], 'system', 'system meta', 'public gateway capabilities and hard limits', { aliases: [['meta']], egressClass: 'gateway', handler: 'meta', outputType: 'record' }),
  command('system.doctor', ['system', 'doctor'], 'system', 'system doctor', 'run bounded local diagnostics', { aliases: [['doctor']], surfaces: CLI, sideEffect: 'local-admin', handler: 'doctor', outputType: 'record' }),
  command('system.policy', ['system', 'policy'], 'system', 'system policy', 'show active shell and provider policy metadata', { handler: 'system-policy', outputType: 'record' }),
  command('system.limits', ['system', 'limits'], 'system', 'system limits', 'show execution and pipeline limits', { handler: 'limits', outputType: 'record' }),
  command('system.capabilities', ['system', 'capabilities'], 'system', 'system capabilities', 'show surface capabilities', { handler: 'capabilities', outputType: 'records' }),
  command('system.setup', ['system', 'setup'], 'system', 'system setup', 'run the fixed PARA11AX setup workflow', { aliases: [['setup']], surfaces: CLI, sideEffect: 'local-admin', handler: 'setup' }),
  command('system.repair', ['system', 'repair'], 'system', 'system repair', 'run the fixed PARA11AX repair workflow', { aliases: [['repair']], surfaces: CLI, sideEffect: 'local-admin', handler: 'repair' }),
  command('system.release-verify', ['system', 'release', 'verify'], 'system', 'system release verify', 'verify the release manifest and repository state', { aliases: [['release', 'verify']], surfaces: CLI, sideEffect: 'local-admin', handler: 'release-verify' }),
  command('system.maltego-check', ['system', 'maltego', 'check'], 'system', 'system maltego check', 'validate the Maltego integration', { aliases: [['maltego', 'check']], surfaces: CLI, sideEffect: 'local-admin', handler: 'maltego-check' }),

  // Intelligence / enrichment
  command('intel.enrich', ['enrich'], 'intel', 'enrich <observable> [--fast|--standard|--full]', 'run bounded Evidence v2 enrichment', { aliases: [['scan'], ['pivot']], auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'enrich', outputType: 'enrichment' }),
  command('intel.intel', ['intel'], 'intel', 'intel <observable>', 'enrich an automatically classified observable', { auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'enrich', outputType: 'enrichment' }),
  ...['ip', 'domain', 'url', 'hash', 'cve', 'asn', 'cidr', 'certificate'].map(type => command(`intel.${type}`, ['intel', type], 'intel', `intel ${type} <observable>`, `enrich a validated ${type} observable`, { auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'intel-typed', outputType: 'enrichment' })),
  command('intel.batch', ['batch'], 'intel', 'batch <observable> [observable ...]', 'enrich 1..20 observables with the active profile', { auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'batch', outputType: 'records' }),
  command('intel.profile', ['profile'], 'intel', 'profile [fast|standard|full]', 'show or set the fixed enrichment profile', { sideEffect: 'session', handler: 'profile', completion: { values: ['fast', 'standard', 'full'] } }),
  command('intel.normalize', ['normalize'], 'intel', 'normalize <observable>', 'normalize an observable without provider work', { handler: 'normalize', outputType: 'record' }),
  command('intel.type', ['type'], 'intel', 'type <observable>', 'classify an observable without provider work', { handler: 'type', outputType: 'scalar' }),
  command('intel.validate', ['validate'], 'intel', 'validate <observable>', 'validate an observable without provider work', { handler: 'validate', outputType: 'record' }),

  // Provider namespace
  command('provider.list', ['provider', 'list'], 'provider', 'provider list', 'list provider metadata', { aliases: [['providers', 'list']], handler: 'provider-list', outputType: 'records' }),
  command('provider.show', ['provider', 'show'], 'provider', 'provider show <provider>', 'show one provider contract', { handler: 'provider-show', outputType: 'record' }),
  command('provider.status', ['provider', 'status'], 'provider', 'provider status [provider]', 'show provider readiness state', { auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'provider-status', outputType: 'records' }),
  command('provider.probe', ['provider', 'probe'], 'provider', 'provider probe <provider|all>', 'run sequential bounded provider probes', { aliases: [['providers', 'probe']], surfaces: CLI, sideEffect: 'local-admin', handler: 'provider-probe', outputType: 'records' }),
  command('provider.capabilities', ['provider', 'capabilities'], 'provider', 'provider capabilities <provider>', 'show provider observable and policy capabilities', { handler: 'provider-capabilities', outputType: 'record' }),
  command('provider.coverage', ['provider', 'coverage'], 'provider', 'provider coverage <observable-type>', 'show providers covering an observable type', { handler: 'provider-coverage', outputType: 'records' }),
  command('provider.run', ['provider', 'run'], 'provider', 'provider run <provider> <observable>', 'run one policy-bound registered provider', { auth: 'required', egressClass: 'provider', capabilities: ['provider-read'], handler: 'provider-run', outputType: 'enrichment' }),
  command('provider.env-template', ['provider', 'env-template'], 'provider', 'provider env-template', 'print canonical provider environment placeholders', { aliases: [['providers', 'env-template']], surfaces: CLI, sideEffect: 'local-admin', handler: 'provider-env-template' }),

  // Direct provider analyst front doors
  ...[
    ['vt', 'virustotal'], ['gn', 'greynoise'], ['otx', 'otx'], ['urlscan', 'urlscan'], ['threatfox', 'threatfox'],
    ['malwarebazaar', 'malwarebazaar'], ['rdap', 'rdap'], ['epss', 'epss'], ['kev', 'cisa-kev'], ['nvd', 'nvd'], ['censys', 'censys'],
  ].map(([token, provider]) => command(`provider.alias.${token}`, [token], 'provider', `${token} <observable>`, `run ${provider} through the bounded provider gateway`, { auth: 'required', egressClass: 'provider', capabilities: ['provider-read'], handler: 'provider-run', outputType: 'enrichment', provider })),

  // Specialist OSINT
  command('osint.shodan', ['shodan'], 'osint', 'shodan <host|search|count|stats|domain|info> ...', 'run bounded Shodan operator queries', { auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'shodan', outputType: 'record' }),
  command('osint.greynoise-swarm', ['swarm'], 'osint', 'swarm <search|get|export|unique|timeseries> ...', 'query bounded GreyNoise Project Swarm sessions and pivots', { surfaces: WEB, auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'swarm', outputType: 'record', completion: { values: ['search', 'get', 'export', 'unique', 'timeseries'] } }),
  command('osint.user-scanner', ['user-scanner'], 'osint', 'user-scanner <email|username> <target> [options]', 'run isolated identity OSINT', { aliases: [['osint'], ['identity']], auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], handler: 'user-scanner', outputType: 'record', completion: { values: ['email', 'username'] } }),

  // Result and evidence
  command('result.summary', ['result', 'summary'], 'result', 'result summary', 'render current result summary', { aliases: [['overview'], ['ovr'], ['last']], inputTypes: ['void', 'enrichment'], handler: 'result-summary' }),
  command('result.request', ['result', 'request'], 'result', 'result request', 'show current request metadata', { aliases: [['request']], inputTypes: ['void', 'enrichment'], handler: 'result-request', outputType: 'record' }),
  command('result.evidence', ['result', 'evidence'], 'result', 'result evidence', 'project current evidence records', { aliases: [['evidence'], ['evd']], inputTypes: ['void', 'enrichment'], handler: 'result-evidence', outputType: 'evidence' }),
  command('result.facts', ['result', 'facts'], 'result', 'result facts', 'project analyst facts', { inputTypes: ['void', 'enrichment'], handler: 'result-facts', outputType: 'records' }),
  command('result.providers', ['result', 'providers'], 'result', 'result providers', 'show providers represented in the current result', { aliases: [['providers']], inputTypes: ['void', 'enrichment'], handler: 'result-providers', outputType: 'provider-list' }),
  command('result.failures', ['result', 'failures'], 'result', 'result failures', 'show provider failures', { aliases: [['failures'], ['failed']], inputTypes: ['void', 'enrichment'], handler: 'result-failures', outputType: 'records' }),
  command('result.contradictions', ['result', 'contradictions'], 'result', 'result contradictions', 'show evidence contradictions', { aliases: [['contradictions']], inputTypes: ['void', 'enrichment'], handler: 'result-contradictions', outputType: 'records' }),
  command('result.corroboration', ['result', 'corroboration'], 'result', 'result corroboration', 'show corroborated evidence', { aliases: [['corroboration']], inputTypes: ['void', 'enrichment'], handler: 'result-corroboration', outputType: 'records' }),
  command('result.references', ['result', 'references'], 'result', 'result references', 'show source references', { aliases: [['references']], inputTypes: ['void', 'enrichment'], handler: 'result-references', outputType: 'records' }),
  command('result.relationships', ['result', 'relationships'], 'result', 'result relationships', 'project explicit relationships', { aliases: [['relationships'], ['rel']], inputTypes: ['void', 'enrichment'], handler: 'result-relationships', outputType: 'relationships' }),
  command('result.coverage', ['result', 'coverage'], 'result', 'result coverage', 'show provider and semantic coverage', { aliases: [['coverage'], ['cov']], inputTypes: ['void', 'enrichment'], handler: 'result-coverage', outputType: 'record' }),
  command('result.correlation', ['result', 'correlation'], 'result', 'result correlation', 'show current correlation model', { aliases: [['correlation'], ['cor']], inputTypes: ['void', 'enrichment'], handler: 'result-correlation', outputType: 'record' }),
  command('result.graph', ['result', 'graph'], 'result', 'result graph', 'show the evidence graph', { inputTypes: ['void', 'enrichment'], handler: 'result-graph', outputType: 'graph' }),
  command('result.guidance', ['result', 'guidance'], 'result', 'result guidance', 'show analyst guidance', { inputTypes: ['void', 'enrichment'], handler: 'result-guidance', outputType: 'guidance' }),
  command('result.decision', ['result', 'decision'], 'result', 'result decision', 'show decision support', { inputTypes: ['void', 'enrichment'], handler: 'result-decision', outputType: 'record' }),
  command('result.attacks', ['result', 'attacks'], 'result', 'result attacks', 'show ATT&CK mappings', { inputTypes: ['void', 'enrichment'], handler: 'result-attacks', outputType: 'records' }),
  command('result.hunts', ['result', 'hunts'], 'result', 'result hunts', 'show generated hunt opportunities', { inputTypes: ['void', 'enrichment'], handler: 'result-hunts', outputType: 'records' }),
  command('result.telemetry', ['result', 'telemetry'], 'result', 'result telemetry', 'show telemetry guidance', { inputTypes: ['void', 'enrichment'], handler: 'result-telemetry', outputType: 'record' }),
  command('result.freshness', ['result', 'freshness'], 'result', 'result freshness', 'show evidence freshness state', { inputTypes: ['void', 'enrichment'], handler: 'result-freshness', outputType: 'records' }),
  command('result.raw', ['result', 'raw'], 'result', 'result raw', 'return raw Evidence v2 enrichment', { aliases: [['raw']], inputTypes: ['void', 'enrichment'], handler: 'result-raw', outputType: 'enrichment' }),
  command('result.view', ['view'], 'result', 'view <overview|evidence|correlation|relationships|coverage|raw>', 'render a legacy result view', { inputTypes: ['void', 'enrichment'], handler: 'view', completion: { values: ['overview', 'evidence', 'correlation', 'relationships', 'coverage', 'raw'] } }),

  // Deterministic analyst mission workspace
  command('mission.new', ['mission', 'new'], 'mission', 'mission new', 'create an empty volatile mission workspace', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-new', outputType: 'record' }),
  command('mission.show', ['mission', 'show'], 'mission', 'mission show', 'show the current mission workspace', { inputTypes: ['void', 'record'], handler: 'mission-show', outputType: 'record' }),
  command('mission.profile-set', ['mission', 'profile', 'set'], 'mission', 'mission profile set <json>', 'set the normalized client profile', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-profile-set', outputType: 'record' }),
  command('mission.context-set', ['mission', 'context', 'set'], 'mission', 'mission context set <json>', 'set explicit threat relevance context', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-context-set', outputType: 'record' }),
  command('mission.relevance', ['mission', 'relevance'], 'mission', 'mission relevance', 'calculate deterministic client relevance', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-relevance', outputType: 'record' }),
  command('mission.hunt-build', ['mission', 'hunt', 'build'], 'mission', 'mission hunt build <json>', 'build an evidence-bound hunt package', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-hunt-build', outputType: 'record' }),
  command('mission.kql-validate', ['mission', 'kql', 'validate'], 'mission', 'mission kql validate <query>', 'validate KQL against the bounded static schema', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-kql-validate', outputType: 'record' }),
  command('mission.result-analyze', ['mission', 'result', 'analyze'], 'mission', 'mission result analyze <json-or-csv>', 'analyze bounded hunt results without evidence promotion', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-result-analyze', outputType: 'record' }),
  command('mission.servicenow', ['mission', 'servicenow'], 'mission', 'mission servicenow', 'build a projection-only ServiceNow record', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-servicenow', outputType: 'record' }),
  command('mission.export', ['mission', 'export'], 'mission', 'mission export', 'create a deterministic in-memory mission artifact', { inputTypes: ['void', 'record'], handler: 'mission-export', outputType: 'artifact' }),
  command('mission.import', ['mission', 'import'], 'mission', 'mission import', 'import one explicit bounded mission bundle', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-import', outputType: 'record' }),
  command('mission.clear', ['mission', 'clear'], 'mission', 'mission clear', 'clear volatile mission content', { inputTypes: ['void', 'record'], sideEffect: 'session', handler: 'mission-clear', outputType: 'record' }),

  // Cases
  command('case.new', ['case', 'new'], 'case', 'case new <title>', 'create a local analyst case', { surfaces: WEB, sideEffect: 'session', handler: 'case-new' }),
  command('case.open', ['case', 'open'], 'case', 'case open <id>', 'open a local analyst case', { surfaces: WEB, sideEffect: 'session', handler: 'case-open' }),
  command('case.close', ['case', 'close'], 'case', 'case close', 'close the active local case', { surfaces: WEB, sideEffect: 'session', handler: 'case-close' }),
  command('case.list', ['case', 'list'], 'case', 'case list', 'list local analyst cases', { surfaces: WEB, handler: 'case-list', outputType: 'records' }),
  command('case.show', ['case', 'show'], 'case', 'case show', 'show the active local case', { surfaces: WEB, handler: 'case-show', outputType: 'record' }),
  command('case.refresh', ['case', 'refresh'], 'case', 'case refresh [--stale]', 'refresh case observables through bounded enrichment', { surfaces: WEB, auth: 'required', egressClass: 'gateway', capabilities: ['gateway-read'], sideEffect: 'session', handler: 'case-refresh', outputType: 'records' }),
  command('case.import', ['case', 'import'], 'case', 'case import', 'import a validated PARA11AX case bundle', { surfaces: WEB, sideEffect: 'session', handler: 'case-import' }),
  command('case.export', ['case', 'export'], 'case', 'case export', 'export the active case bundle', { surfaces: WEB, sideEffect: 'browser-download', handler: 'case-export', outputType: 'artifact' }),
  command('case.find', ['case', 'find'], 'case', 'case find <type> <value>', 'find exact observable sightings in local cases', { surfaces: WEB, handler: 'case-find', outputType: 'records' }),
  command('case.pins', ['case', 'pins'], 'case', 'case pins', 'show active case pins', { surfaces: WEB, handler: 'case-pins', outputType: 'records' }),
  command('case.notes', ['case', 'notes'], 'case', 'case notes', 'show active case notes', { surfaces: WEB, handler: 'case-notes', outputType: 'records' }),
  command('case.timeline', ['case', 'timeline'], 'case', 'case timeline', 'show active case timeline', { surfaces: WEB, handler: 'case-timeline', outputType: 'records' }),
  command('case.graph', ['case', 'graph'], 'case', 'case graph', 'show active case evidence graph', { surfaces: WEB, handler: 'case-graph', outputType: 'graph' }),
  command('case.pin', ['case', 'pin'], 'case', 'case pin', 'pin the current result', { aliases: [['pin']], surfaces: WEB, sideEffect: 'session', handler: 'case-pin' }),
  command('case.unpin', ['case', 'unpin'], 'case', 'case unpin <type> <value>', 'remove one exact pin', { aliases: [['unpin']], surfaces: WEB, sideEffect: 'session', handler: 'case-unpin' }),
  command('case.note', ['case', 'note'], 'case', 'case note <text>', 'append an analyst note', { aliases: [['note']], surfaces: WEB, sideEffect: 'session', handler: 'case-note' }),
  command('case.diff', ['case', 'diff'], 'case', 'case diff', 'show latest semantic case diff', { aliases: [['diff']], surfaces: WEB, handler: 'case-diff', outputType: 'records' }),

  // Investigation Workspace v2
  command('investigation.new', ['investigation', 'new'], 'investigation', 'investigation new <title>', 'create and activate a local investigation', { aliases: [['inv', 'new']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-new', outputType: 'record' }),
  command('investigation.open', ['investigation', 'open'], 'investigation', 'investigation open <id>', 'open a local investigation', { aliases: [['inv', 'open']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-open', outputType: 'record' }),
  command('investigation.close', ['investigation', 'close'], 'investigation', 'investigation close', 'close the active investigation', { aliases: [['inv', 'close']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-close', outputType: 'record' }),
  command('investigation.list', ['investigation', 'list'], 'investigation', 'investigation list', 'list local investigations', { aliases: [['inv', 'list']], surfaces: WEB, handler: 'investigation-list', outputType: 'records' }),
  command('investigation.show', ['investigation', 'show'], 'investigation', 'investigation show [--file <path>|--stdin]', 'show the active or explicitly supplied investigation state', { aliases: [['inv', 'show']], handler: 'investigation-show', outputType: 'record' }),
  command('investigation.status', ['investigation', 'status'], 'investigation', 'investigation status [--file <path>|--stdin]', 'show deterministic workflow readiness, gaps, and stale artifacts', { aliases: [['inv', 'status']], handler: 'investigation-status', outputType: 'record' }),
  command('investigation.scope-set', ['investigation', 'scope', 'set'], 'investigation', 'investigation scope set <json>', 'set normalized client scope and explicit context', { aliases: [['inv', 'scope', 'set']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-scope-set', outputType: 'record' }),
  command('investigation.observable-add', ['investigation', 'observable', 'add'], 'investigation', 'investigation observable add <type> <value>', 'add one canonical scoped observable', { aliases: [['inv', 'observable', 'add']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-observable-add', outputType: 'record' }),
  command('investigation.observable-remove', ['investigation', 'observable', 'remove'], 'investigation', 'investigation observable remove <type> <value>', 'remove one exact scoped observable', { aliases: [['inv', 'observable', 'remove']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-observable-remove', outputType: 'record' }),
  command('investigation.capture-evidence', ['investigation', 'capture', 'evidence'], 'investigation', 'investigation capture evidence', 'explicitly capture the current Evidence v2 result', { aliases: [['inv', 'capture', 'evidence']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-capture-evidence', outputType: 'record' }),
  command('investigation.capture-operator', ['investigation', 'capture', 'operator'], 'investigation', 'investigation capture operator', 'capture the current Shodan, User Scanner, or GreyNoise Swarm read result as context', { aliases: [['inv', 'capture', 'operator']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-capture-operator', outputType: 'record' }),
  command('investigation.relevance', ['investigation', 'relevance'], 'investigation', 'investigation relevance', 'build deterministic client relevance', { aliases: [['inv', 'relevance']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-relevance', outputType: 'record' }),
  command('investigation.hunt-build', ['investigation', 'hunt', 'build'], 'investigation', 'investigation hunt build <json>', 'build an evidence-bound hunt package', { aliases: [['inv', 'hunt', 'build']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-hunt-build', outputType: 'record' }),
  command('investigation.kql-validate', ['investigation', 'kql', 'validate'], 'investigation', 'investigation kql validate <query>', 'validate KQL against the bounded static schema', { aliases: [['inv', 'kql', 'validate']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-kql-validate', outputType: 'record' }),
  command('investigation.result-import', ['investigation', 'result', 'import'], 'investigation', 'investigation result import', 'import bounded external query results', { aliases: [['inv', 'result', 'import']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-result-import', outputType: 'record' }),
  command('investigation.disposition-set', ['investigation', 'disposition', 'set'], 'investigation', 'investigation disposition set <json>', 'record explicit analyst judgment', { aliases: [['inv', 'disposition', 'set']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-disposition-set', outputType: 'record' }),
  command('investigation.report', ['investigation', 'report'], 'investigation', 'investigation report', 'build a current deterministic investigation report', { aliases: [['inv', 'report']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-report', outputType: 'record' }),
  command('investigation.servicenow', ['investigation', 'servicenow'], 'investigation', 'investigation servicenow', 'build a projection-only ServiceNow record', { aliases: [['inv', 'servicenow']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-servicenow', outputType: 'record' }),
  command('investigation.timeline', ['investigation', 'timeline'], 'investigation', 'investigation timeline', 'show bounded investigation history', { aliases: [['inv', 'timeline']], surfaces: WEB, handler: 'investigation-timeline', outputType: 'records' }),
  command('investigation.export', ['investigation', 'export'], 'investigation', 'investigation export [--file <path>|--stdin]', 'download or print a canonical investigation bundle', { aliases: [['inv', 'export']], sideEffect: 'browser-download', handler: 'investigation-export', outputType: 'artifact' }),
  command('investigation.import', ['investigation', 'import'], 'investigation', 'investigation import [--file <path>|--stdin]', 'import or validate one explicit bounded investigation bundle', { aliases: [['inv', 'import']], sideEffect: 'session', handler: 'investigation-import', outputType: 'record' }),
  command('investigation.clear', ['investigation', 'clear'], 'investigation', 'investigation clear', 'remove the active local investigation', { aliases: [['inv', 'clear']], surfaces: WEB, sideEffect: 'session', handler: 'investigation-clear', outputType: 'record' }),

  // Reports
  command('report.show', ['report', 'show'], 'report', 'report show', 'render current analyst report', { inputTypes: ['void', 'enrichment'], handler: 'report-show' }),
  command('report.quality', ['report', 'quality'], 'report', 'report quality', 'run the report quality gate', { inputTypes: ['void', 'enrichment'], handler: 'report-quality', outputType: 'record' }),
  command('report.compile', ['report', 'compile'], 'report', 'report compile <snapshot> <output-dir> [preset]', 'compile deterministic report artifacts', { surfaces: CLI, sideEffect: 'filesystem', handler: 'report-compile', outputType: 'artifact' }),
  command('report.diff', ['report', 'diff'], 'report', 'report diff <before> <after>', 'compare two bounded report snapshots', { surfaces: CLI, sideEffect: 'filesystem', handler: 'report-diff', outputType: 'record' }),
  ...['text', 'html', 'pdf', 'csv', 'kql', 'navigator', 'stix', 'evidence', 'manifest'].map(format => command(`report.${format}`, ['report', format], 'report', `report ${format}`, `render ${format} report output`, { surfaces: format === 'manifest' ? CLI : BOTH, inputTypes: ['void', 'enrichment'], handler: `report-${format}`, outputType: format === 'manifest' ? 'record' : 'artifact' })),

  // Export
  command('export.json', ['json'], 'export', 'json [save]', 'print or download Evidence v2 JSON', { inputTypes: ['void', 'enrichment'], sideEffect: 'browser-download', handler: 'json', outputType: 'text' }),
  command('export.stix', ['stix'], 'export', 'stix', 'generate STIX 2.1 from the current observable', { auth: 'required', inputTypes: ['void', 'enrichment'], egressClass: 'gateway', capabilities: ['gateway-read'], sideEffect: 'browser-download', handler: 'stix', outputType: 'artifact' }),
  command('export.copy', ['copy'], 'export', 'copy <observable|report|json|request-id>', 'copy a bounded current-result projection', { surfaces: WEB, inputTypes: ['void', 'enrichment'], handler: 'copy' }),
  command('export.download', ['download'], 'export', 'download <artifact>', 'download a registered in-memory artifact', { surfaces: WEB, inputTypes: ['artifact'], sideEffect: 'browser-download', handler: 'download', outputType: 'artifact' }),

  // Terminal/local display
  command('terminal.clear', ['clear'], 'terminal', 'clear', 'clear terminal scrollback', { aliases: [['cls']], surfaces: WEB, sideEffect: 'session', handler: 'clear' }),
  command('terminal.echo', ['echo'], 'terminal', 'echo [text]', 'echo local text without shell evaluation', { handler: 'echo' }),
  command('terminal.printf', ['printf'], 'terminal', 'printf <text>', 'print local text without shell evaluation', { handler: 'printf' }),
  command('terminal.date', ['date'], 'terminal', 'date', 'print local time', { handler: 'date' }),
  command('terminal.hostname', ['hostname'], 'terminal', 'hostname', 'print PARA11AX terminal hostname', { handler: 'hostname' }),
  command('terminal.pwd', ['pwd'], 'terminal', 'pwd', 'print virtual working directory', { handler: 'pwd' }),
  command('terminal.uname', ['uname'], 'terminal', 'uname', 'print virtual PARA11AX runtime identity', { handler: 'uname' }),
  command('terminal.id', ['id'], 'terminal', 'id', 'print virtual analyst identity', { handler: 'id' }),
  command('terminal.theme', ['theme'], 'terminal', 'theme', 'show PARA11AX semantic palette', { surfaces: WEB, handler: 'theme' }),
  command('terminal.sound', ['sound'], 'terminal', 'sound <on|off>', 'enable or mute synthesized terminal audio', { surfaces: WEB, sideEffect: 'session', handler: 'sound', completion: { values: ['on', 'off'] } }),
  command('terminal.volume', ['volume'], 'terminal', 'volume <0-100>', 'set synthesized terminal volume', { surfaces: WEB, sideEffect: 'session', handler: 'volume' }),

  // Safe internal transforms
  ...[
    ['where', 'records'], ['select', 'records'], ['fields', 'records'], ['sort', 'records'], ['unique', 'records'], ['count', 'scalar'], ['group', 'records'],
    ['pluck', 'records'], ['head', 'records'], ['tail', 'records'], ['jsonpath', 'scalar'], ['grep', 'text'], ['wc', 'scalar'], ['uniq', 'text'],
  ].map(([name, outputType]) => command(`transform.${name}`, [name], 'transform', `${name} ...`, `apply the safe internal ${name} transform`, { inputTypes: name === 'grep' || name === 'wc' || name === 'uniq' ? ['text'] : name === 'jsonpath' ? ['record', 'records', 'enrichment', 'evidence', 'graph', 'guidance'] : ['records'], outputType, handler: name })),
];

export const COMMAND_DESCRIPTORS = Object.freeze(commands);
export const COMMAND_REGISTRY = createCommandRegistry(COMMAND_DESCRIPTORS);
