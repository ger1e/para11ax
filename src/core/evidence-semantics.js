const FACT_CLASSES = new Set([
  'network_context',
  'certificate_context',
  'vulnerability_metadata',
  'attack_knowledge',
  'exploitation',
  'supply_chain',
  'web_archive_observation',
  'legal_entity_context',
]);
const CONTEXT_CLASSES = new Set([
  'threat_context',
  'malware_association',
  'malware_similarity',
]);
const KNOWLEDGE_CLASSES = new Set(['defensive_knowledge']);
const FACT_SOURCES = new Set(['authoritative', 'first_party']);

export function evidenceRole({ semanticClass, sourceRole } = {}) {
  if (KNOWLEDGE_CLASSES.has(semanticClass)) return 'knowledge_only';
  if (sourceRole === 'contextual' || CONTEXT_CLASSES.has(semanticClass)) return 'contextual_intelligence';
  if (FACT_SOURCES.has(sourceRole) && FACT_CLASSES.has(semanticClass)) return 'observed_fact';
  return 'provider_claim';
}
