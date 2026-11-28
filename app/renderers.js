import { buildIpAnalystReport, renderIpAnalystReportText } from './view-model.js';

if (typeof document !== 'undefined' && !document.querySelector('link[href="/app/analyst-facts.css"]')) {
  const styles = document.createElement('link');
  styles.rel = 'stylesheet';
  styles.href = '/app/analyst-facts.css';
  document.head.append(styles);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function inline(value) {
  if (value == null) return '—';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(inline).join(', ');
  if (typeof value === 'object') {
    if (typeof value.url === 'string') return value.url;
    return Object.entries(value).map(([key, item]) => `${key}=${inline(item)}`).join(' · ');
  }
  return String(value);
}

function displayFactValue(fact) {
  const value = inline(fact?.value);
  return fact?.sources?.length ? `${value}  // ${fact.sources.join(' + ')}` : value;
}

function appendFacts(target, facts, empty = '') {
  if (!facts?.length) {
    if (empty) target.append(el('p', 'empty-state', empty));
    return;
  }
  const grid = el('dl', 'fact-grid');
  for (const fact of facts) {
    const row = el('div', 'fact-row');
    const value = el('dd', 'fact-value', displayFactValue(fact));
    if (/^SOURCE \d+$/.test(fact.label) && typeof fact.value === 'string') {
      try {
        const url = new URL(fact.value);
        if (url.protocol === 'https:' && !url.username && !url.password) {
          const anchor = el('a', 'reference', fact.value);
          anchor.href = url.href;
          anchor.target = '_blank';
          anchor.rel = 'noopener noreferrer';
          value.replaceChildren(anchor);
        }
      } catch {}
    }
    row.append(el('dt', 'fact-label', fact.label), value);
    grid.append(row);
  }
  target.append(grid);
}

function factCard(item, className = 'fact-card') {
  const card = el('article', className);
  if (item.title) card.append(el('h3', 'fact-title', item.title));
  appendFacts(card, item.facts || []);
  return card;
}

function sectionLabel(title) {
  return el('h2', 'view-label analyst-section-label', title);
}

function overviewContent(model) {
  const panel = el('section', `overview tone-${model.tone}`);
  const fields = [
    ['STATUS', String(model.status || 'unknown').toUpperCase()], ['TYPE', model.type], ['INDICATOR', model.indicator],
    ['PROFILE', model.profile], ['DURATION', model.durationMs == null ? '—' : `${model.durationMs} ms`],
    ['FRESHNESS', model.freshness], ['HUNTABILITY', model.huntability?.level ?? '—'],
    ['OK', model.providerSummary.ok ?? 0], ['FAILED', model.providerSummary.failed ?? 0],
    ['NOT RUN', model.providerSummary.skipped ?? 0], ['CACHED', model.providerSummary.cached ?? 0],
  ];
  for (const [label, value] of fields) {
    const cell = el('div', 'hud-cell');
    cell.append(el('span', 'hud-label', label), el('strong', 'hud-value', value));
    panel.append(cell);
  }
  panel.append(el('p', 'coverage-line', `COVERAGE // ${model.coverage}`));
  if (model.huntability?.rationale) panel.append(el('p', 'hunt-rationale', model.huntability.rationale));
  if (model.limitations?.length) {
    const limits = el('div', 'analyst-limitations');
    limits.append(el('strong', 'analyst-limitations-label', 'LIMITATIONS'));
    for (const limitation of model.limitations) limits.append(el('p', 'signal-meta', limitation));
    panel.append(limits);
  }
  return panel;
}

function evidenceContent(cards) {
  const wrap = el('section', 'evidence-list');
  if (!cards.length) {
    wrap.append(el('p', 'empty-state', 'No evidence items returned. Absence of evidence is not a benign verdict.'));
    return wrap;
  }
  for (const card of cards) {
    const article = el('article', `signal semantic-${card.semanticClass}`);
    const head = el('header', 'signal-head');
    head.append(el('p', 'signal-provider', card.provider), el('p', 'signal-kind', card.kind));
    article.append(head);
    if (card.verdict !== null) article.append(el('strong', 'signal-verdict', String(card.verdict).toUpperCase()));
    if (card.semanticNote) article.append(el('p', 'semantic-note', card.semanticNote));

    const primary = [];
    if (card.confidence !== null) primary.push({ label: 'CONFIDENCE', value: card.confidence });
    if (card.firstSeen) primary.push({ label: 'FIRST SEEN', value: card.firstSeen });
    if (card.lastSeen) primary.push({ label: 'LAST SEEN', value: card.lastSeen });
    if (card.malwareFamily) primary.push({ label: 'MALWARE', value: card.malwareFamily });
    if (card.tags.length) primary.push({ label: 'TAGS', value: card.tags.join(', ') });
    appendFacts(article, primary);

    if (card.actorFacts.length) {
      article.append(el('h3', 'fact-subtitle', 'ACTOR / ATTRIBUTION FACTS'));
      appendFacts(article, card.actorFacts);
    }
    if (card.attributeFacts.length) {
      article.append(el('h3', 'fact-subtitle', 'OBSERVED FACTS'));
      appendFacts(article, card.attributeFacts);
    }

    const details = el('details', 'signal-details');
    details.append(el('summary', null, 'TECHNICAL / PROVENANCE'));
    appendFacts(details, [
      { label: 'CACHE', value: card.cacheState ?? 'unknown' },
      { label: 'RETRIEVED', value: card.retrievedAt ?? 'unknown' },
      { label: 'PARSER', value: card.parserVersion ?? 'unknown' },
      { label: 'FINGERPRINT', value: card.fingerprint ?? 'unavailable' },
    ]);
    for (const reference of card.references) {
      const line = el('p', 'reference-line');
      const raw = inline(reference);
      let linked = false;
      const candidate = typeof reference === 'string' ? reference : reference?.url;
      if (typeof candidate === 'string') {
        try {
          const url = new URL(candidate);
          if (url.protocol === 'https:') {
            const link = el('a', 'reference', raw);
            link.href = url.href;
            link.rel = 'noopener noreferrer';
            link.target = '_blank';
            line.append(link);
            linked = true;
          }
        } catch {}
      }
      if (!linked) line.append(el('span', 'reference', raw));
      details.append(line);
    }
    article.append(details);
    wrap.append(article);
  }
  return wrap;
}

function correlationContent(model) {
  const section = el('section', 'correlation-grid');
  appendFacts(section, [
    { label: 'FRESHNESS', value: model.freshness },
    { label: 'HUNTABILITY', value: model.huntability?.level ?? 'unknown' },
    ...(model.attributionConfidence !== null ? [{ label: 'ATTRIBUTION CONFIDENCE', value: inline(model.attributionConfidence) }] : []),
  ]);
  if (model.huntability?.rationale) section.append(el('p', 'signal-meta', model.huntability.rationale));

  const corroboration = el('section', 'corroboration-list');
  corroboration.append(sectionLabel('CORROBORATION'));
  for (const item of model.corroboration) corroboration.append(factCard(item, 'fact-card corroboration'));
  if (!model.corroboration.length) corroboration.append(el('p', 'empty-state', 'No independent same-class corroboration emitted.'));
  section.append(corroboration);

  const contradictions = el('section', 'contradiction-list');
  contradictions.append(sectionLabel('CONTRADICTIONS'));
  for (const item of model.contradictions) contradictions.append(factCard(item, 'fact-card contradiction'));
  if (!model.contradictions.length) contradictions.append(el('p', 'empty-state', 'No contradictions emitted.'));
  section.append(contradictions);

  const axes = el('section', 'risk-axes');
  axes.append(sectionLabel('CVE RISK AXES'));
  for (const [name, value] of Object.entries(model.riskAxes)) {
    const row = el('div', `risk-axis risk-${name}`);
    row.append(el('strong', 'risk-axis-label', name.toUpperCase()), el('code', 'risk-axis-value', value.display));
    axes.append(row);
  }
  section.append(axes);
  return section;
}

function relationshipsContent(relationships) {
  const chain = el('section', 'relationship-chain');
  for (const relationship of relationships) chain.append(factCard(relationship, 'fact-card relationship'));
  if (!relationships.length) chain.append(el('p', 'empty-state', 'No explicit relationships emitted.'));
  return chain;
}

function coverageContent(model) {
  const panel = el('section', 'coverage');
  panel.append(el('p', 'coverage-summary', model.summaryText));
  if (!model.failures.length) {
    panel.append(el('p', 'empty-state', 'No provider failures reported.'));
    return panel;
  }
  for (const failure of model.failures) {
    const card = el('article', `coverage-failure failure-${failure.state}`);
    const header = el('header', 'failure-head');
    header.append(
      el('strong', 'failure-provider', failure.provider),
      el('span', 'failure-state', failure.state.toUpperCase()),
    );
    card.append(header, el('strong', 'failure-label', failure.label), el('p', 'failure-summary', failure.summary));
    appendFacts(card, failure.details);
    panel.append(card);
  }
  return panel;
}

function ipSignalLine(item) {
  const details = el('details', `fact-card ip-source-line ip-source-details semantic-${item.semanticClass || 'evidence'}`);
  const summary = el('summary', 'ip-source-summary');
  summary.append(
    el('strong', 'signal-provider', item.provider),
    el('span', 'signal-kind', item.kind),
    el('strong', 'signal-verdict', item.verdict),
  );
  details.append(summary);
  if (item.semanticNote) details.append(el('p', 'semantic-note', item.semanticNote));
  appendFacts(details, item.facts || []);
  return details;
}

function ipActionLine(item) {
  const article = el('article', 'fact-card ip-action-line');
  if (item.title) article.append(el('h3', 'fact-title ip-action-title', item.title));
  appendFacts(article, item.facts || []);
  const details = el('details', 'ip-action-details');
  details.append(el('summary', null, 'HUNT DETAIL / TUNING / KQL'));
  appendFacts(details, item.detailFacts || []);
  article.append(details);
  return article;
}

function compactFailureLine(failure) {
  const article = el('article', `coverage-failure ip-failure-line failure-${failure.state}`);
  const header = el('header', 'failure-head');
  header.append(el('strong', 'failure-provider', failure.provider), el('span', 'failure-state', failure.label));
  article.append(header, el('p', 'failure-summary', failure.summary));
  appendFacts(article, failure.details || []);
  return article;
}

function ipReportContent(models) {
  const report = buildIpAnalystReport(models);
  const root = el('section', 'analyst-brief ip-intelligence-report');
  root.setAttribute('aria-label', report.title || 'IP INTELLIGENCE REPORT');

  const heading = el('header', 'brief-section ip-report-header');
  heading.append(el('h1', 'fact-title ip-report-title', report.title || 'IP INTELLIGENCE REPORT'));
  heading.append(el('p', 'coverage-line', `${String(report.status || 'unknown').toUpperCase()} · PROFILE ${String(report.profile || 'unknown').toUpperCase()} · ${report.durationMs ?? '—'} ms`));
  const reportText = renderIpAnalystReportText(report);
  const ascii = el('details', 'brief-section ip-ascii-report');
  const copy = el('button', 'report-copy', 'COPY ASCII REPORT');
  copy.type = 'button';
  const summary = el('summary', 'view-label', 'ASCII REPORT / NFO VIEW');
  const pre = el('pre', 'shell-pre');
  const borderWidth = 90;
  const border = '+' + '-'.repeat(borderWidth + 2) + '+';
  const wrapped = reportText.trimEnd().split('\n').flatMap(line => {
    if (!line) return [''];
    if (/^SOURCE \d+: https?:\/\//.test(line)) return [line];
    const words = line.split(/\s+/);
    const rows = [];
    let current = '';
    for (const word of words) {
      if (current && current.length + word.length + 1 > borderWidth) { rows.push(current); current = ''; }
      current += (current ? ' ' : '') + word;
    }
    if (current) rows.push(current);
    return rows;
  });
  const width = Math.max(borderWidth, ...wrapped.map(line => line.length));
  const edge = width === borderWidth ? border : '+' + '-'.repeat(width + 2) + '+';
  const framed = [edge, ...wrapped.map(line => '| ' + line.padEnd(width) + ' |'), edge].join('\n');
  pre.textContent = framed;
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(framed); copy.textContent = 'COPIED'; }
    catch { copy.textContent = 'COPY FAILED / SELECT TEXT'; }
  });
  heading.append(copy);
  ascii.append(summary, pre);
  root.append(heading, ascii);

  const assessment = el('section', 'brief-section ip-report-assessment ip-at-a-glance');
  assessment.append(sectionLabel('EXECUTIVE ASSESSMENT'));
  assessment.append(el('strong', 'signal-verdict ip-assessment-state', report.assessment.state));
  assessment.append(el('p', 'failure-summary ip-assessment-summary', report.assessment.summary));
  appendFacts(assessment, report.assessment.facts);
  root.append(assessment);

  for (const section of report.sections) {
    const block = el('section', `brief-section ip-report-section ip-section-${section.id}`);
    block.append(sectionLabel(section.title));
    if (section.summary) block.append(el('p', 'coverage-summary', section.summary));
    appendFacts(block, section.facts || []);

    if (section.id === 'coverage') {
      if (!section.failures?.length) block.append(el('p', 'empty-state', 'No provider failures reported.'));
      for (const failure of section.failures || []) block.append(compactFailureLine(failure));
      root.append(block);
      continue;
    }

    if (section.id === 'analyst-actions') {
      if (!section.items?.length) block.append(el('p', 'empty-state', 'No deterministic analyst actions emitted.'));
      for (const item of section.items || []) block.append(ipActionLine(item));
      root.append(block);
      continue;
    }

    if (section.id === 'related-infrastructure' || section.id === 'correlation' || section.id === 'attack-behavior') {
      if (!section.items?.length) block.append(el('p', 'empty-state', section.id === 'related-infrastructure' ? 'No explicit related infrastructure emitted.' : 'No corroboration or contradiction records emitted.'));
      for (const item of section.items || []) block.append(factCard(item, `fact-card ${item.tone || 'relationship'}`));
      root.append(block);
      continue;
    }

    if (section.items?.length) {
      const sources = el('div', 'ip-source-list');
      for (const item of section.items) sources.append(ipSignalLine(item));
      block.append(sources);
    } else if (!section.facts?.length && section.id !== 'huntability') {
      block.append(el('p', 'empty-state', 'No reportable observations in this category.'));
    }
    root.append(block);
  }
  return root;
}

export function clear(target) {
  while (target.firstChild) target.removeChild(target.firstChild);
}

export function renderOverview(target, model) {
  clear(target);
  target.append(overviewContent(model));
}

export function renderEvidence(target, cards) {
  clear(target);
  target.append(evidenceContent(cards));
}

export function renderCorrelation(target, model) {
  clear(target);
  target.append(correlationContent(model));
}

export function renderRelationships(target, relationships) {
  clear(target);
  target.append(relationshipsContent(relationships));
}

export function renderCoverage(target, model) {
  clear(target);
  target.append(coverageContent(model));
}

export function renderFacts(target, title, facts, tone = '') {
  clear(target);
  const section = el('section', `fact-section${tone ? ` fact-${tone}` : ''}`);
  section.append(sectionLabel(title));
  appendFacts(section, facts, 'No facts available.');
  target.append(section);
}

export function renderBrief(target, { overview, evidence, correlation, relationships, coverage }) {
  clear(target);
  if (overview.type === 'ip') {
    target.append(ipReportContent({ overview, evidence, correlation, relationships, coverage }));
    return;
  }

  const brief = el('section', 'analyst-brief');

  const summarySection = el('section', 'brief-section brief-summary');
  summarySection.append(sectionLabel('SUMMARY'), overviewContent(overview));
  brief.append(summarySection);

  const evidenceSection = el('section', 'brief-section brief-evidence');
  evidenceSection.append(sectionLabel('EVIDENCE'), evidenceContent(evidence));
  brief.append(evidenceSection);

  const correlationSection = el('section', 'brief-section brief-correlation');
  correlationSection.append(sectionLabel('CORRELATION / RISK'), correlationContent(correlation));
  brief.append(correlationSection);

  const relationshipSection = el('section', 'brief-section brief-relationships');
  relationshipSection.append(sectionLabel('RELATIONSHIPS'), relationshipsContent(relationships));
  brief.append(relationshipSection);

  const coverageSection = el('section', 'brief-section brief-coverage');
  coverageSection.append(sectionLabel('FAILURES / COVERAGE'), coverageContent(coverage));
  brief.append(coverageSection);

  target.append(brief);
}

export function renderRaw(target, lines, query = '') {
  clear(target);
  const needle = String(query).toLowerCase();
  const pre = el('pre', 'raw-console');
  for (const line of lines) {
    if (needle && !line.text.toLowerCase().includes(needle)) continue;
    const row = el('span', 'code-line');
    row.append(el('span', 'line-number', line.number), el('span', 'line-text', line.text));
    pre.append(row);
  }
  target.append(pre);
}
