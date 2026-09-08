import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(path, 'utf8');

const LOCKUP = 'assets/brand/para11ax-radar-lockup.svg';
const HERO_RADAR = 'assets/brand/para11ax-radar.svg';
const RAIN = 'assets/brand/para11ax-rain.svg';
const BRAND_RUNTIME = 'brand-unification.js';
const BRAND_CSS = 'brand-unification.css';
const ADAPTER = 'landing-terminal-v7.js';

test('shared browser logo surfaces still resolve the canonical compact radar lockup', () => {
  for (const path of [LOCKUP, BRAND_RUNTIME, BRAND_CSS]) assert.equal(existsSync(path), true, `${path} must exist`);
  const runtime = read(BRAND_RUNTIME);
  const landing = read(ADAPTER);
  const app = read('app/terminal-main.js');
  assert.match(runtime, /LOCKUP_URL\s*=\s*['"]\/assets\/brand\/para11ax-radar-lockup\.svg['"]/i);
  assert.match(runtime, /\.terminal-brand/);
  assert.match(runtime, /\.terminal-mark/);
  assert.match(runtime, /\.para11ax-logo/);
  assert.match(landing, /import\(['"]\.\/brand-unification\.js['"]\)\.catch/i, 'landing must load branding as fail-safe progressive enhancement');
  assert.match(app, /await\s+import\(['"]\.\.\/brand-unification\.js['"]\)/i);
});

test('shared compact lockup is one moving PPI radar plus angular PARA11AX wordmark', () => {
  const svg = read(LOCKUP);
  assert.equal((svg.match(/data-radar=["']ppi["']/gi) ?? []).length, 1);
  assert.match(svg, /<animateTransform\b[^>]*type=["']rotate["']/i);
  assert.match(svg, /data-wordmark=["']para11ax-angular-a["']/i);
  assert.match(svg, /PARA/i);
  assert.match(svg, /11/i);
  assert.match(svg, /AX/i);
  assert.match(svg, /#39FF14/i);
  assert.match(svg, /prefers-reduced-motion:\s*reduce/i);
  assert.doesNotMatch(svg, /prefers-reduced-motion:\s*reduce[^}]*\.motion\s*\{\s*display:\s*none/is, 'reduced-motion must not freeze the radar');
  assert.doesNotMatch(svg, /sentinel|helmet|visor|shield/i);
});

test('production landing owns a browser-native PPI while standalone SVG remains reusable', () => {
  assert.equal(existsSync(HERO_RADAR), true);
  const html = read('index.html');
  const css = read('landing-radar-motion.css');
  const svg = read(HERO_RADAR);
  assert.equal((html.match(/data-radar=["']ppi["']/gi) ?? []).length, 1, 'production landing must have one radar');
  assert.match(html, /@keyframes\s+radar-spin/i);
  assert.match(html, /\.radar-sweep[^}]*animation:\s*radar-spin\s+4\.8s/is);
  assert.doesNotMatch(html, /<img[^>]*para11ax-radar\.svg/i);
  assert.match(css, /@keyframes\s+radar-live-spin/i, 'legacy landing enhancement must also use browser-native CSS motion');
  assert.doesNotMatch(css, /background\s*:\s*url\([^)]*para11ax-radar\.svg/i);
  assert.equal((svg.match(/data-radar=["']ppi["']/gi) ?? []).length, 1);
  assert.match(svg, /@keyframes\s+ppi-spin/i);
});

test('landing rain mirrors the GER1E vertical glyph-stream treatment at higher density', () => {
  assert.equal(existsSync(RAIN), true);
  const css = read('landing-radar-motion.css');
  const svg = read(RAIN);
  assert.match(css, /\.matrix-rain[^}]*para11ax-rain\.svg/i);
  assert.match(css, /\.matrix-rain\s*>\s*\.rain[^}]*display:\s*none/i);
  const animations = svg.match(/<animateTransform\b[^>]*type=["']translate["'][^>]*>/gi) ?? [];
  assert.ok(animations.length >= 40, `expected at least 40 staggered rain tracks, got ${animations.length}`);
  for (const glyph of ['ヘ', 'カ', '尺', '乇', 'シ', 'キ']) assert.match(svg, new RegExp(glyph), `rain must preserve GER1E glyph ${glyph}`);
  assert.match(svg, /class=["'][^"']*dim[^"']*["']/i, 'rain must retain a dim secondary depth layer');
  assert.match(svg, /#39FF14/i, 'PARA11AX rain must remain phosphor green');
  assert.doesNotMatch(svg, /[01]{24,}/, 'rain must use vertical glyph streams rather than long horizontal binary strings');
});

test('landing adapter constructs neither radar nor rain and reveals content before enhancement', () => {
  const js = read(ADAPTER);
  assert.doesNotMatch(js, /function\s+enhanceRadar\s*\(/i);
  assert.doesNotMatch(js, /RADAR_CONTACTS|EXTRA_RAIN_COLUMNS|densifyRain/i);
  assert.doesNotMatch(js, /['"]radar-sweep['"]|['"]radar-trail['"]|['"]radar-pulse['"]/i);
  assert.doesNotMatch(js, /function\s+mountMinimalHero\s*\(/i);
  const revealIndex = js.indexOf('revealAll();');
  const importIndex = js.indexOf("import('./brand-unification.js')");
  assert.ok(revealIndex >= 0 && importIndex > revealIndex);
});

test('shared brand runtime stays visual-only and non-persistent', () => {
  const js = read(BRAND_RUNTIME);
  assert.doesNotMatch(js, /fetch\s*\(|XMLHttpRequest|WebSocket|EventSource/i);
  assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB|document\.cookie/i);
  assert.doesNotMatch(js, /AudioContext|webkitAudioContext|new\s+Audio\s*\(/i);
});

test('reduced motion keeps every radar visible and moving more slowly', () => {
  const html = read('index.html');
  const css = read('landing-radar-motion.css');
  const svg = read(HERO_RADAR);
  assert.match(html, /prefers-reduced-motion:\s*reduce[\s\S]*radar-sweep[^}]*animation-duration:\s*24s/is);
  assert.match(css, /prefers-reduced-motion:\s*reduce[\s\S]*ghost-ring[^}]*animation-duration:\s*24s/is);
  assert.match(svg, /prefers-reduced-motion:\s*reduce[\s\S]*ppi-sweep[^}]*animation-duration:\s*24s/is);
});

test('there is one sweep per radar surface and no legacy CSS pseudo-radar overlays', () => {
  const brandCss = read(BRAND_CSS);
  const landingCss = read('landing-radar-motion.css');
  assert.doesNotMatch(brandCss, /para11ax-lockup-radar-spin/i);
  assert.doesNotMatch(brandCss, /\.terminal-brand::after|\.terminal-mark::after|\.shell-brand::after|\.boot-brand-lockup::after/i);
  assert.equal((landingCss.match(/@keyframes\s+radar-live-spin/gi) ?? []).length, 1);
});

test('PPI sweep is narrow, range rings are restrained, and contacts have phosphor persistence', () => {
  const html = read('index.html');
  const css = read('landing-radar-motion.css');
  const heroSvg = read(HERO_RADAR);
  const lockupSvg = read(LOCKUP);

  for (const source of [html, css]) {
    assert.doesNotMatch(source, /306deg|318deg|342deg/, 'the old broad luminous sector must be gone');
    assert.match(source, /radar-contact/i, 'landing radar must render explicit contacts instead of baking blips into the background');
  }

  assert.match(html, /@keyframes\s+radar-contact-echo/i, 'contacts must decay like phosphor returns');
  assert.match(html, /\.radar-center[^}]*width:\s*4px[^}]*height:\s*4px/is, 'center pip must remain small');
  assert.doesNotMatch(heroSvg, /M260 260L481 202A228 228 0 0 1 484 303Z/, 'standalone radar must not use the old wide wedge');
  assert.doesNotMatch(lockupSvg, /M0 0 28-8A29 29 0 0 1 28 8Z/, 'compact lockup must not use the old wide wedge');
});

test('landing PPI follows the GER1E README single-line sweep contract', () => {
  const html = read('index.html');
  const css = read('landing-radar-motion.css');
  const heroSvg = read(HERO_RADAR);

  const productionSweep = html.match(/\.radar-sweep\s*\{([^}]*)\}/is)?.[1] ?? '';
  const productionBeam = html.match(/\.radar-sweep:before\s*\{([^}]*)\}/is)?.[1] ?? '';
  const legacySweep = css.match(/\.hero-ghost>\.ghost-ring\s*\{([^}]*)\}/is)?.[1] ?? '';
  const legacyBeam = css.match(/\.hero-ghost>\.ghost-ring::before\s*\{([^}]*)\}/is)?.[1] ?? '';

  assert.doesNotMatch(productionSweep, /conic-gradient/i, 'production sweep must not render a second luminous sector');
  assert.doesNotMatch(legacySweep, /conic-gradient/i, 'legacy sweep must not render a second luminous sector');
  assert.doesNotMatch(productionBeam, /rotate\(/i, 'beam itself must stay radial; only the sweep wrapper rotates');
  assert.doesNotMatch(legacyBeam, /rotate\(/i, 'legacy beam itself must stay radial; only the sweep wrapper rotates');
  assert.match(productionBeam, /left:\s*50%[^}]*top:\s*50%[^}]*transform-origin:\s*left center/is, 'production beam must originate at radar center');
  assert.match(legacyBeam, /left:\s*50%[^}]*top:\s*50%[^}]*transform-origin:\s*left center/is, 'legacy beam must originate at radar center');
  assert.doesNotMatch(heroSvg, /<path[^>]+fill=["']#39FF14["'][^>]+fill-opacity=/i, 'standalone radar sweep must be the README-style rotating line, not a wedge');
  assert.match(heroSvg, /<g class=["']ppi-sweep["'][^>]*>[\s\S]*?<path d=["']M260 260H486["'][^>]*stroke=/i, 'standalone radar line must rotate from the center toward the rim');
});
