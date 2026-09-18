const SOURCE_COUNT = '39';
const CANONICAL_PALETTE = [
  'void       #020403  terminal background',
  'phosphor   #39FF14  primary radar / verified state',
  'white      #F7FFF6  primary terminal text',
  'muted      #8DA391  secondary terminal text',
  'red        #FF2438  failure / contradiction / anomaly',
].join('\n');

function scrubLegacyBootArt() {
  const ascii = document.getElementById('pepe-ascii');
  if (!ascii) return;
  ascii.replaceChildren();
  ascii.hidden = true;
  ascii.setAttribute('aria-hidden', 'true');
  ascii.removeAttribute('aria-label');
}

function normalizeSourceCount(root = document) {
  for (const node of root.querySelectorAll?.('.shell-footer-center,.shell-footer-mobile') || []) {
    node.textContent = node.textContent.replace(/\b\d{1,3} SOURCES\b/, `${SOURCE_COUNT} SOURCES`);
    node.textContent = node.textContent.replace(/\b\d{1,3} SRC\b/, `${SOURCE_COUNT} SRC`);
  }
}

function normalizePaletteOutput(root = document) {
  for (const node of root.querySelectorAll?.('.shell-pre,.shell-line') || []) {
    const text = node.textContent || '';
    if (text.includes('#050608') && text.includes('#00E5FF') && text.includes('#39FF88')) {
      node.textContent = CANONICAL_PALETTE;
    }
  }
}

function normalizeBrand(root = document) {
  scrubLegacyBootArt();
  normalizeSourceCount(root);
  normalizePaletteOutput(root);
}

normalizeBrand();

const workspace = document.getElementById('workspace');
if (workspace && typeof MutationObserver === 'function') {
  const observer = new MutationObserver(records => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node?.nodeType === 1) normalizeBrand(node);
      }
    }
    normalizeBrand(workspace);
  });
  observer.observe(workspace, { childList: true, subtree: true });
}
