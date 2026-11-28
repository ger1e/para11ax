const media = globalThis.matchMedia?.('(prefers-reduced-motion: reduce)');
const reduced = () => Boolean(media?.matches);
const CURSOR_HREF = '/site-cursor.css';
const MOTION_HREF = '/landing-radar-motion.css';
const DESKTOP_FIT_HREF = '/landing-desktop-fit.css';
const PROMPT_TEXT = 'analyst@para11ax:~$';
const LEGACY_PROMPTS = ['user@para11ax:~$', 'user@para11ax: ~', 'para11ax@gateway:~$'];

document.documentElement.dataset.terminalMotion = 'v7';

const reveal = node => node?.classList.add('is-visible');
const revealAll = () => document.querySelectorAll('[data-reveal]').forEach(reveal);

// Critical content is visible first. Branding/motion are progressive enhancement only.
revealAll();

function ensureStylesheet(href) {
  if (document.querySelector(`link[href="${href}"]`)) return;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = href;
  document.head.append(link);
}

function normalizePromptIdentity() {
  for (const node of document.querySelectorAll('.terminal-session .session-line')) {
    let value = node.textContent || '';
    for (const legacy of LEGACY_PROMPTS) value = value.replaceAll(legacy, PROMPT_TEXT);
    node.textContent = value;
  }
}

ensureStylesheet(CURSOR_HREF);
ensureStylesheet(MOTION_HREF);
ensureStylesheet(DESKTOP_FIT_HREF);
normalizePromptIdentity();

// Never let a branding adapter failure hide the landing page.
void import('./brand-unification.js').catch(() => {});

const hero = document.querySelector('.terminal-hero');
let glitchTimer = null;
let resetTimer = null;

function scheduleGlitch() {
  if (reduced() || !hero || document.hidden || glitchTimer !== null || resetTimer !== null) return;
  glitchTimer = globalThis.setTimeout(() => {
    glitchTimer = null;
    if (reduced() || document.hidden) return;
    hero.classList.add('is-glitching');
    resetTimer = globalThis.setTimeout(() => {
      resetTimer = null;
      hero.classList.remove('is-glitching');
      scheduleGlitch();
    }, 280);
  }, 6800 + Math.floor(Math.random() * 4200));
}

function clearMotionTimers() {
  if (glitchTimer != null) globalThis.clearTimeout(glitchTimer);
  if (resetTimer != null) globalThis.clearTimeout(resetTimer);
  glitchTimer = null;
  resetTimer = null;
  hero?.classList.remove('is-glitching');
}

scheduleGlitch();
media?.addEventListener?.('change', event => {
  if (event.matches) clearMotionTimers();
  else if (!glitchTimer && !resetTimer) scheduleGlitch();
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) clearMotionTimers();
  else { revealAll(); scheduleGlitch(); }
});

export {
  clearMotionTimers,
  normalizePromptIdentity,
  revealAll,
};
