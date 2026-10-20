import { buildIpAnalystReport } from './view-model.js';

const WIDTH = 88;
const clean = (value) => String(value ?? '—').replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim();
const clip = (value, max = WIDTH - 5) => {
  const chars = [...clean(value)];
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : chars.join('');
};
function line(text = '') { return '│ ' + clip(text).padEnd(WIDTH - 4) + ' │'; }
const border = (left, right) => left + '─'.repeat(WIDTH - 2) + right;
const heading = (title) => [border('┌', '┐'), line(title), border('├', '┤')];
const end = () => border('└', '┘');
function appendLink(container, label, href) {
  if (typeof href !== 'string' || !/^https:\/\/[^\s]+$/i.test(href)) return;
  const row = document.createElement('div');
  row.className = 'ascii-intel-link';
  row.append(document.createTextNode('  ↳ ' + clean(label) + ': '));
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.textContent = href;
  anchor.target = '_blank';
  anchor.rel = 'noopener noreferrer';
  row.append(anchor);
  container.append(row);
}
export function renderAsciiIpIntelligence(target, envelope, models) {
  const report = buildIpAnalystReport(models);
  target.replaceChildren();
  const root = document.createElement('section');
  root.className = 'ascii-intel';
  root.setAttribute('aria-label', 'PARA11AX IP intelligence ASCII report');
  const pre = document.createElement('pre');
  pre.className = 'ascii-intel-art';
  const rows = [
    border('╔', '╗'),
    '║' + ' PARA11AX // LIVE IP INTELLIGENCE'.padEnd(WIDTH - 2) + '║',
    border('╚', '╝'),
    line('TARGET: ' + envelope.indicator + '  |  STATUS: ' + envelope.status.toUpperCase()),
    line('PROFILE: ' + envelope.profile + '  |  REQUEST: ' + envelope.requestId),
    line('PROVIDERS: ' + (models.coverage?.summaryText ?? 'unavailable')),
    ...heading('EXECUTIVE ASSESSMENT'),
    line('STATE: ' + (report.assessment?.state ?? 'UNKNOWN')),
    ...wrapRows(report.assessment?.summary ?? 'No assessment emitted.'),
    ...factRows(report.assessment?.facts),
    end(),
  ];
  for (const section of report.sections || []) {
    rows.push(...heading(section.title));
    if (section.summary) rows.push(...wrapRows(section.summary));
    rows.push(...factRows(section.facts));
    for (const item of section.items || []) {
      rows.push(line('• ' + (item.title ?? item.provider ?? item.kind ?? 'OBSERVATION') + (item.verdict ? ' / ' + item.verdict : '')));
      rows.push(...factRows(item.facts));
      if (item.semanticNote) rows.push(...wrapRows('NOTE: ' + item.semanticNote));
    }
    for (const failure of section.failures || []) rows.push(line('! ' + (failure.provider ?? 'provider') + ': ' + (failure.label ?? failure.reason ?? 'unavailable')));
    if (!section.facts?.length && !section.items?.length && !section.failures?.length) rows.push(line('NOT REPORTED BY AVAILABLE SOURCES'));
    rows.push(end());
  }
  pre.textContent = rows.join('\n');
  root.append(pre);
  const links = document.createElement('div');
  links.className = 'ascii-intel-links';
  const label = document.createElement('pre');
  label.textContent = '┌─ SOURCE EVIDENCE / CLICKABLE INVESTIGATION LINKS ───────────────┐';
  links.append(label);
  const seen = new Set();
  let count = 0;
  for (const evidence of envelope.evidence || []) {
    for (const ref of evidence.references || []) {
      const url = typeof ref === 'string' ? ref : ref?.url ?? ref?.href;
      if (!url || seen.has(url)) continue;
      seen.add(url);
      appendLink(links, evidence.provider || 'source', url);
      count++;
    }
  }
  if (!count) {
    const empty = document.createElement('div');
    empty.textContent = '  No provider evidence URLs returned. No links invented.';
    links.append(empty);
  }
  root.append(links);
  target.append(root);
}
function wrapRows(value) {
  const words = clean(value).split(' ');
  const rows = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > WIDTH - 5 && current) {
      rows.push(line(current));
      current = '';
    }
    current += (current ? ' ' : '') + word;
  }
  if (current) rows.push(line(current));
  return rows;
}
function factRows(facts) {
  const rows = [];
  for (const fact of facts || []) {
    rows.push(...wrapRows(clean(fact.label) + ': ' + clean(fact.value)));
    if (fact.sources?.length) rows.push(line('  SOURCE: ' + fact.sources.join(', ')));
  }
  return rows;
}
