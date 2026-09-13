const LOGO_URL = '/app/para11ax-mark.svg';

const GLOBE_LANDMASSES = Object.freeze([
  'M58 73 L72 62 L88 60 L100 67 L97 78 L107 88 L101 98 L91 96 L84 107 L74 102 L69 91 L58 86 L51 78 Z',
  'M96 108 L108 112 L117 124 L114 139 L108 149 L105 164 L98 178 L91 167 L89 150 L84 136 L88 121 Z',
  'M93 50 L105 46 L113 53 L109 64 L98 67 L90 58 Z',
  'M126 75 L138 70 L148 75 L145 84 L153 91 L149 103 L157 113 L153 129 L145 143 L137 160 L128 153 L124 135 L117 121 L120 107 L115 95 L121 86 Z',
  'M145 72 L160 66 L179 68 L193 76 L201 88 L193 99 L181 102 L173 114 L159 110 L151 99 L141 94 L147 84 Z',
  'M171 145 L184 140 L197 147 L194 159 L182 166 L169 160 L164 151 Z',
]);

const CUE_CLASSES = Object.freeze([
  'cue-auth-up', 'cue-auth-down', 'cue-busy', 'cue-success', 'cue-partial',
  'cue-error', 'cue-contradiction', 'cue-export', 'cue-complete', 'cue-history',
]);

let activeClockTimer = null;
const cueTimers = new WeakMap();

if (
  document.documentElement.dataset.terminalFirst !== 'v7'
  && !document.querySelector('link[href="/app/shell-polish.css"]')
) {
  const styles = document.createElement('link');
  styles.rel = 'stylesheet';
  styles.href = '/app/shell-polish.css';
  document.head.append(styles);
}

function createLogo(className = '') {
  const logo = document.createElement('img');
  logo.className = `para11ax-logo${className ? ` ${className}` : ''}`;
  logo.src = LOGO_URL;
  logo.alt = 'PARA11AX';
  logo.decoding = 'async';
  return logo;
}

function enhanceBootGlobe() {
  const globe = document.querySelector('.boot-globe');
  if (!globe || globe.dataset.enhanced === 'true') return;
  const ns = 'http://www.w3.org/2000/svg';
  const grid = globe.querySelector('.boot-globe-grid');

  const landmasses = document.createElementNS(ns, 'g');
  landmasses.classList.add('boot-globe-landmasses');
  for (const pathData of GLOBE_LANDMASSES) {
    const landmass = document.createElementNS(ns, 'path');
    landmass.setAttribute('d', pathData);
    landmass.classList.add('boot-globe-landmass');
    landmasses.append(landmass);
  }

  if (grid) grid.prepend(landmasses);
  else globe.prepend(landmasses);

  const scanner = document.createElementNS(ns, 'ellipse');
  scanner.setAttribute('cx', '120');
  scanner.setAttribute('cy', '120');
  scanner.setAttribute('rx', '38');
  scanner.setAttribute('ry', '88');
  scanner.classList.add('boot-globe-scanner');
  (grid || globe).append(scanner);

  globe.dataset.enhanced = 'true';
}

function decorateBootBrand() {
  const standby = document.querySelector('.boot-standby');
  if (!standby || standby.querySelector('.boot-brand-lockup')) return;
  const legacyLabel = standby.querySelector('span:last-child');
  const lockup = document.createElement('span');
  lockup.className = 'boot-brand-lockup';
  const meta = document.createElement('span');
  meta.className = 'boot-brand-meta';
  meta.textContent = 'GATEWAY // COLD START';
  lockup.append(createLogo(), meta);
  legacyLabel?.replaceWith(lockup);
  if (!lockup.isConnected) standby.append(lockup);
}

function decorateShellBrand() {
  const brand = document.querySelector('.shell-brand');
  if (!brand || brand.querySelector('.shell-logo')) return;
  const version = brand.textContent.match(/\b\d+\.\d+\.\d+\b/)?.[0] || '2.0.0';
  brand.dataset.version = version;
  const label = document.createElement('span');
  label.className = 'shell-brand-label';
  label.textContent = `Gateway Terminal ${version}`;
  brand.replaceChildren(createLogo('shell-logo'), label);
}

function formatClockParts(date) {
  const hour = String(date.getHours()).padStart(2, '0');
  const minute = String(date.getMinutes()).padStart(2, '0');
  const second = String(date.getSeconds()).padStart(2, '0');
  const weekday = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'][date.getDay()];
  const day = String(date.getDate()).padStart(2, '0');
  const month = String(date.getMonth() + 1).padStart(2, '0');
  let zone = '';
  try {
    zone = new Intl.DateTimeFormat('en', { timeZoneName: 'short' })
      .formatToParts(date)
      .find(part => part.type === 'timeZoneName')?.value || '';
  } catch {}
  return { hour, minute, second, weekday, day, month, zone };
}

function createClock() {
  const clock = document.createElement('time');
  clock.className = 'shell-clock';
  clock.setAttribute('aria-label', 'Local time');

  const hm = document.createElement('span');
  hm.className = 'shell-clock-hm';
  const seconds = document.createElement('span');
  seconds.className = 'shell-clock-seconds';
  const meta = document.createElement('span');
  meta.className = 'shell-clock-meta';
  clock.append(hm, seconds, meta);

  const tickClock = () => {
    const date = new Date();
    const parts = formatClockParts(date);
    hm.textContent = `${parts.hour}:${parts.minute}`;
    seconds.textContent = `:${parts.second}`;
    meta.textContent = `${parts.weekday} ${parts.day}-${parts.month}${parts.zone ? ` · ${parts.zone}` : ''}`;
    clock.dateTime = date.toISOString();
  };

  tickClock();
  if (activeClockTimer) clearInterval(activeClockTimer);
  activeClockTimer = setInterval(tickClock, 1000);
  return clock;
}

function createFooterLed(label, state = 'idle') {
  const item = document.createElement('span');
  item.className = 'shell-footer-led';
  item.dataset.state = state;
  const dot = document.createElement('i');
  dot.setAttribute('aria-hidden', 'true');
  const text = document.createElement('span');
  text.textContent = label;
  item.append(dot, text);
  return item;
}

function createFooter(version) {
  const footer = document.createElement('footer');
  footer.className = 'shell-footer';

  const desktop = document.createElement('span');
  desktop.className = 'shell-footer-desktop';
  desktop.textContent = 'PARA11AX // CTI ENRICHMENT';

  const center = document.createElement('span');
  center.className = 'shell-footer-center';
  center.textContent = '40 SOURCES · EVIDENCE v2 · READ ONLY';

  const leds = document.createElement('span');
  leds.className = 'shell-footer-leds';
  leds.append(
    createFooterLed('GATEWAY', 'context'),
    createFooterLed('EVIDENCE', 'idle'),
    createFooterLed('PROVIDERS', 'idle'),
    createFooterLed('AUTH', 'down'),
  );

  const build = document.createElement('span');
  build.className = 'shell-footer-build';
  build.textContent = `v${version}`;

  const mobile = document.createElement('span');
  mobile.className = 'shell-footer-mobile';
  mobile.textContent = `CTI ENRICHMENT · 40 SRC · v${version}`;

  footer.append(desktop, center, leds, build, mobile);
  return footer;
}

function pulseCue(root, cue, duration = 420) {
  if (!root || !CUE_CLASSES.includes(cue)) return;
  const previous = cueTimers.get(root);
  if (previous) clearTimeout(previous);
  for (const item of CUE_CLASSES) root.classList.remove(item);
  void root.offsetWidth;
  root.classList.add(cue);
  cueTimers.set(root, setTimeout(() => {
    root.classList.remove(cue);
    cueTimers.delete(root);
  }, duration));
}

function updateFooterState(root, state = {}) {
  const footer = root.querySelector('.shell-footer');
  if (!footer) return;
  const byLabel = new Map([...footer.querySelectorAll('.shell-footer-led')].map(item => [item.textContent.trim(), item]));
  const auth = byLabel.get('AUTH');
  const evidence = byLabel.get('EVIDENCE');
  const providers = byLabel.get('PROVIDERS');
  if (auth) auth.dataset.state = state.authenticated ? 'ok' : 'down';
  if (evidence && state.evidence) evidence.dataset.state = state.evidence;
  if (providers && state.providers) providers.dataset.state = state.providers;
}

function classifyTranscriptCue(text) {
  const value = String(text || '');
  if (/contradiction/i.test(value)) return 'cue-contradiction';
  if (/STIX 2\.1 bundle exported/i.test(value)) return 'cue-export';
  if (/\[\s*PARTIAL\s*\]/i.test(value)) return 'cue-partial';
  if (/\[\s*(ERROR|FAILED)\s*\]|command failed|gateway unavailable/i.test(value)) return 'cue-error';
  if (/\[\s*OK\s*\]/i.test(value)) return 'cue-success';
  return '';
}

function decorateShellChrome() {
  const root = document.querySelector('.unix-shell');
  const status = root?.querySelector('.shell-status');
  const prompt = root?.querySelector('.shell-prompt');
  const scrollback = root?.querySelector('.shell-scrollback');
  if (!root || !status || !prompt || !scrollback || root.dataset.chrome === 'true') return;

  decorateShellBrand();
  const brand = root.querySelector('.shell-brand');
  const version = brand?.dataset.version || '2.0.0';
  const sessionState = root.querySelector('.shell-session-state');

  const clock = createClock();
  status.append(clock);

  const scannerTrack = document.createElement('div');
  scannerTrack.className = 'scanner-track shell-scanner-track';
  scannerTrack.setAttribute('aria-hidden', 'true');
  scannerTrack.append(document.createElement('i'));
  status.after(scannerTrack);

  const footer = createFooter(version);
  prompt.after(footer);
  root.dataset.chrome = 'true';

  let previousAuth = sessionState?.textContent.includes('AUTH:UP') || false;
  let previousBusy = sessionState?.textContent.includes('BUSY') || false;
  updateFooterState(root, { authenticated: previousAuth });

  if (sessionState && typeof MutationObserver === 'function') {
    const stateObserver = new MutationObserver(() => {
      const text = sessionState.textContent || '';
      const auth = text.includes('AUTH:UP');
      const busy = text.includes('BUSY');
      if (auth !== previousAuth) pulseCue(root, auth ? 'cue-auth-up' : 'cue-auth-down');
      if (busy && !previousBusy) pulseCue(root, 'cue-busy');
      if (!busy && previousBusy) pulseCue(root, 'cue-complete');
      previousAuth = auth;
      previousBusy = busy;
      updateFooterState(root, { authenticated: auth, providers: busy ? 'active' : undefined });
    });
    stateObserver.observe(sessionState, { childList: true, characterData: true, subtree: true });
  }

  const promptLabel = root.querySelector('.shell-prompt-label');
  if (promptLabel && typeof MutationObserver === 'function') {
    const promptObserver = new MutationObserver(() => {
      root.classList.toggle('secret-mode', promptLabel.textContent.trim() === 'BEARER:');
    });
    promptObserver.observe(promptLabel, { childList: true, characterData: true, subtree: true });
  }

  if (typeof MutationObserver === 'function') {
    const transcriptObserver = new MutationObserver(records => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          const text = node.textContent || '';
          const cue = classifyTranscriptCue(text);
          if (!cue) continue;
          pulseCue(root, cue, cue === 'cue-contradiction' ? 520 : 420);
          if (cue === 'cue-success' || cue === 'cue-export') {
            updateFooterState(root, { evidence: 'ok', providers: 'ok' });
            setTimeout(() => pulseCue(root, 'cue-complete', 320), 430);
          } else if (cue === 'cue-partial') {
            updateFooterState(root, { evidence: 'partial', providers: 'partial' });
          } else if (cue === 'cue-error' || cue === 'cue-contradiction') {
            updateFooterState(root, { evidence: cue === 'cue-error' ? 'error' : 'partial', providers: 'error' });
          }
        }
      }
    });
    transcriptObserver.observe(scrollback, { childList: true });
  }

  const input = root.querySelector('.shell-input');
  input?.addEventListener('keydown', event => {
    if (event.key === 'ArrowUp' || event.key === 'ArrowDown') pulseCue(root, 'cue-history', 180);
  }, { capture: true });
}

function endBootGlobe() {
  document.body.classList.remove('boot-running');
}

const initialize = document.getElementById('boot-initialize');
initialize?.addEventListener('click', () => {
  document.body.classList.add('boot-running');
}, { capture: true });

const bootPanel = document.getElementById('boot-panel');
if (bootPanel && typeof MutationObserver === 'function') {
  const bootObserver = new MutationObserver(() => {
    if (bootPanel.hidden) endBootGlobe();
  });
  bootObserver.observe(bootPanel, { attributes: true, attributeFilter: ['hidden'] });
}

const workspace = document.getElementById('workspace');
if (workspace && typeof MutationObserver === 'function') {
  const shellObserver = new MutationObserver(() => {
    decorateShellBrand();
    decorateShellChrome();
  });
  shellObserver.observe(workspace, { childList: true, subtree: true });
}

enhanceBootGlobe();
decorateBootBrand();
decorateShellBrand();
decorateShellChrome();
