const REPUTATION_KINDS = new Set([
  'reputation',
  'ioc_reputation',
  'threat_intelligence',
  'multi_engine_reputation',
  'malicious_url',
  'malware_distribution',
  'phishing_feed',
  'phishing_feed_match',
  'botnet_c2',
]);

const NETWORK_CONTEXT_KINDS = new Set([
  'network_identity',
  'routing',
  'registration',
  'internet_exposure',
  'passive_dns',
  'dns_resolution',
]);

const INTELLIGENCE_KINDS = new Set([
  'credential_exposure',
  'infostealer_exposure',
  'passive_dns_history',
  'domain_ownership_history',
  'malware_configuration',
  'malware_similarity',
  'supply_chain',
  'anonymization_infrastructure',
  'web_archive_observation',
  'secret_exposure',
  'crypto_abuse',
  'legal_entity_context',
  'tls_malware_infrastructure',
  'exploit_maturity',
  'underground_mention',
  'defensive_knowledge',
]);

const SEMANTIC_ALIASES = new Map([
  ['reported_abuse', 'abuse_reports'],
  ['abuse_reports', 'abuse_reports'],
  ['community_intelligence', 'threat_context'],
  ['community_ioc_report', 'threat_context'],
  ['sample_hosts', 'malware_association'],
  ['malware_sample', 'malware_sample_metadata'],
  ['certificate_metadata', 'certificate_context'],
]);

const POSITIVE_VERDICTS = new Set([
  'malicious',
  'suspicious',
  'phishing',
  'associated',
  'listed',
  'malware_sample',
  'known_exploited',
]);

const EXPLICIT_NEGATIVE_VERDICTS = new Set(['benign', 'clean']);
const ABSENCE_VERDICTS = new Set(['no_association', 'not_listed', 'not_found', 'no_result']);

export function semanticClass(kind) {
  const value = typeof kind === 'string' && kind ? kind : 'unknown';
  if (REPUTATION_KINDS.has(value)) return 'reputation';
  if (NETWORK_CONTEXT_KINDS.has(value)) return 'network_context';
  if (INTELLIGENCE_KINDS.has(value)) return value;
  if (value === 'known_exploited') return 'exploitation';
  if (value === 'exploit_probability') return 'exploit_probability';
  if (value === 'vulnerability_metadata' || value === 'vulnerability_catalog' || value === 'open_source_vulnerability') return 'vulnerability_metadata';
  if (value === 'attack_knowledge') return 'attack_knowledge';
  if (value === 'scanner_activity') return 'scanner_activity';
  if (value === 'tor_exit') return 'tor_exit';
  return SEMANTIC_ALIASES.get(value) ?? value;
}

export function polarity(verdict) {
  const value = String(verdict ?? '').toLowerCase();
  if (POSITIVE_VERDICTS.has(value)) return 'positive';
  if (EXPLICIT_NEGATIVE_VERDICTS.has(value)) return 'negative';
  if (ABSENCE_VERDICTS.has(value)) return 'absence';
  return 'neutral';
}

export function isDecisivePolarity(value) {
  return value === 'positive' || value === 'negative';
}
