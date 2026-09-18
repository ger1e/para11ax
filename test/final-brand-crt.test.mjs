import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('production terminal keeps one compact PPI lockup, CRT glass, and the Natural Earth globe', async () => {
  const [prepaint, main, brandCss, brandJs, boot, earthCss, earthJs, lockup] = await Promise.all([
    read('app/prepaint-v7.css'),
    read('app/terminal-main.js'),
    read('app/brand-final.css'),
    read('app/brand-final.js'),
    read('app/boot.js'),
    read('app/earth-globe.css'),
    read('app/earth-globe.js'),
    read('assets/brand/para11ax-radar-lockup.svg'),
  ]);

  assert.match(prepaint, /@import url\('\/app\/brand-final\.css'\);/);
  assert.ok(
    prepaint.indexOf("@import url('/app/brand-final.css');") > prepaint.indexOf("@import url('/site-cursor.css');"),
    'final brand CSS must win the compatibility cascade before first paint',
  );
  assert.match(main, /await import\('\.\/brand-final\.js'\);/);
  assert.ok(
    main.indexOf("await import('./earth-globe.js')") < main.indexOf("await import('./terminal-polish.js')"),
    'Natural Earth must claim the boot globe before legacy polish runs',
  );

  assert.doesNotMatch(brandCss, /\.terminal-mark::before|\.shell-brand::before/,
    'the canonical SVG already contains the PPI; CSS must not prepend another radar');
  assert.match(lockup, /data-radar=["']ppi["']/i);
  assert.match(lockup, /<animateTransform\b[^>]*type=["']rotate["']/i);
  assert.doesNotMatch(brandCss, /\.boot-globe>\*\{display:none!important\}/);
  assert.doesNotMatch(brandCss, /\.boot-globe\{[\s\S]*conic-gradient\(from var\(--ppi-angle\)/);
  assert.match(earthJs, /projectOrthographic/);
  assert.match(earthJs, /requestAnimationFrame/);
  assert.match(earthJs, /globe\.dataset\.enhanced = ['"]true['"]/);
  assert.doesNotMatch(earthJs, /animateTransform|boot-earth-track|translate\(-720/);
  assert.match(earthCss, /\.boot-globe\{[^}]*animation:none!important/);
  assert.doesNotMatch(earthCss, /boot-earth-track/);

  assert.match(brandCss, /\.crt\{[\s\S]*repeating-linear-gradient/);
  assert.match(brandCss, /@keyframes crt-phosphor-flicker/);
  assert.match(brandCss, /prefers-reduced-motion:reduce[\s\S]*\.crt\{animation:none!important\}/);
  assert.match(brandCss, /#pepe-ascii,\.boot-pepe\{display:none!important\}/);

  for (const banned of ['#00E5FF', '#39FF88', '#F6C945']) {
    assert.doesNotMatch(brandCss, new RegExp(banned, 'i'));
  }

  for (const canonical of ['#020403', '#39FF14', '#F7FFF6', '#8DA391', '#FF2438']) {
    assert.match(brandJs, new RegExp(canonical, 'i'));
  }
  assert.match(boot, /provider-registry\]: 39 sources registered/);
  assert.doesNotMatch(boot, /provider-registry\]: (?:37|38) sources registered/);
});
