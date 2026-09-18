import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createAudioEngine } from '../app/audio.js';
import { createPara11axBootSequence, PARA11AX_BOOT_LINES } from '../app/boot.js';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

class FakeParam { setValueAtTime() {} linearRampToValueAtTime() {} exponentialRampToValueAtTime() {} }
class FakeNode { constructor() { this.frequency = new FakeParam(); this.gain = new FakeParam(); } connect() { return this; } start() {} stop() {} }
class FakeAudioContext { constructor() { this.currentTime = 1; this.destination = {}; this.state = 'running'; this.sampleRate = 48000; } createOscillator() { return new FakeNode(); } createGain() { return new FakeNode(); } resume() { return Promise.resolve(); } }

test('PARA11AX service OK wall completes before Pepe and gateway readiness', async () => {
  const stages = [];
  const boot = createPara11axBootSequence({
    audio: { enable: async () => {}, play: () => {}, stopAll: () => {} },
    sleep: async () => {},
    onStage: (name, payload) => stages.push([name, payload]),
  });
  await boot.start();
  const pepeIndex = stages.findIndex(([name]) => name === 'pepe');
  const lineIndexes = stages.map(([name], index) => name === 'boot-line' ? index : -1).filter(index => index >= 0);
  assert.equal(lineIndexes.length, PARA11AX_BOOT_LINES.length);
  assert.ok(lineIndexes.every(index => index < pepeIndex), 'all service lines must render before Pepe');
  assert.ok(pepeIndex < stages.findIndex(([name]) => name === 'target'), 'Pepe must precede final gateway readiness');
});

test('terminal runtime keeps Pepe boot-only and does not restore boot artifacts into shell scrollback', async () => {
  const entry = await read('app/terminal-entry.js');
  assert.doesNotMatch(entry, /bootTranscript/);
  assert.doesNotMatch(entry, /restoreBootTranscript/);
  assert.doesNotMatch(entry, /boot transcript retained/);
  assert.match(entry, /pepe\.hidden = false/);
  assert.match(entry, /mountAnalystShell/);
  assert.doesNotMatch(entry, /pepeSignature|restorePepeSignature|shell-boot-pepe/);
  assert.doesNotMatch(entry, /bootLog\.replaceChildren\(\)[\s\S]{0,400}stage === ['"]boot-line['"]/, 'boot lines must remain visible during the boot sequence itself');
});

test('active analyst shell is an explicitly named accessibility region', async () => {
  const shell = await read('app/shell-ui.js');
  assert.match(shell, /root\.setAttribute\(['"]role['"],\s*['"]region['"]\)/);
  assert.match(shell, /root\.setAttribute\(['"]aria-label['"],\s*['"]PARA11AX interactive analyst shell['"]\)/);
});


test('Pepe boot reveal avoids unbounded per-glyph paint effects', async () => {
  const base = await read('app/app-base.css');
  const deck = await read('app/analyst-deck.css');
  const shell = await read('app/shell.css');
  assert.match(base, /\.boot-pepe\{[^}]*text-shadow:none;[^}]*contain:layout paint style/);
  assert.doesNotMatch(base, /@keyframes pepe-(?:resolve|glitch)\{[^}]*(?:clip-path|filter|text-shadow)/);
  assert.match(deck, /\.boot-pepe\{[^}]*text-shadow:none!important/);
  assert.doesNotMatch(shell, /\.glitch-pepe \.boot-pepe\{[^}]*px-glitch-(?:tear|chroma)/);
});

test('active visual boot never waits for audio unlock settlement', async () => {
  const stages = [];
  let enableCalls = 0;
  const boot = createPara11axBootSequence({
    audio: {
      enable: () => {
        enableCalls += 1;
        return new Promise(() => {});
      },
      play: () => {},
      stopAll: () => {},
    },
    sleep: async () => {},
    onStage: name => stages.push(name),
  });

  const result = await Promise.race([
    boot.start(),
    new Promise(resolve => setTimeout(() => resolve('audio-timeout'), 100)),
  ]);
  assert.equal(result, true);
  assert.equal(enableCalls, 1);
  assert.equal(stages.at(-1), 'ready');
});

test('backspace cue is not suppressed by character typing throttle', async () => {
  let clock = 1000;
  const audio = createAudioEngine({ AudioContextCtor: FakeAudioContext, now: () => clock });
  await audio.enable();
  audio.typing('character');
  const afterCharacter = audio.state().emitted;
  audio.typing('backspace');
  assert.equal(audio.state().emitted, afterCharacter + 1);
  assert.equal(audio.state().lastCue, 'key-backspace');
});

test('duplicate erase reports collapse to one clack without throttling real erases', async () => {
  let clock = 1000;
  const audio = createAudioEngine({ AudioContextCtor: FakeAudioContext, now: () => clock });
  await audio.enable();
  audio.typing('backspace');
  const once = audio.state().emitted;
  audio.typing('backspace');
  assert.equal(audio.state().emitted, once, 'keydown + beforeinput for one erase must not double-fire');
  clock += 20;
  audio.typing('backspace');
  assert.equal(audio.state().emitted, once + 1, 'a later erase must remain audible');
});

test('mobile virtual-keyboard deletion has a beforeinput backspace cue path', async () => {
  const entry = await read('app/terminal-entry.js');
  assert.match(entry, /beforeinput/);
  assert.match(entry, /deleteContentBackward|deleteContentForward/);
  assert.match(entry, /typing\(['"]backspace['"]\)/);
});

test('56k boot cue uses a dedicated long-form PCM handshake instead of the generic tone recipe', async () => {
  const source = await read('app/audio.js');
  assert.match(source, /MODEM_HANDSHAKE_MS\s*=\s*1[01]\d{3}/, 'handshake should run roughly 10-12 seconds');
  assert.match(source, /renderModemHandshake/);
  assert.match(source, /createBuffer\s*\(\s*1\s*,/);
  assert.match(source, /phase reversal|answer carrier|training noise|V\.8/i);
  assert.doesNotMatch(source, /['"]modem-56k['"]\s*:\s*\[/, 'modem must not remain a generic CUES recipe');
});

test('boot waits for the full modem handshake before PARA11AX service initialization', async () => {
  const source = await read('app/boot.js');
  assert.match(source, /MODEM_HANDSHAKE_MS/);
  assert.match(source, /wait\(MODEM_HANDSHAKE_MS\)/);
});

test('mobile shell uses one coherent operational type scale and compact help layout', async () => {
  const css = await read('app/shell.css');
  const entry = await read('app/terminal-entry.js');
  assert.match(css, /--terminal-font\s*:\s*14px/);
  assert.match(css, /--terminal-input\s*:\s*16px/);
  assert.doesNotMatch(css, /@media\(max-width:430px\)[\s\S]*\.shell-pre\{[^}]*font-size:\s*11px/);
  assert.match(css, /@media\(max-width:430px\)[\s\S]*\.shell-help[^}]*white-space:\s*pre-line/);
  assert.match(css, /@media\(max-width:430px\)[\s\S]*\.shell-pre[^}]*white-space:\s*pre-wrap/);
  assert.match(entry, /PARA11AX COMMAND INDEX/);
  assert.match(entry, /classList\.add\(['"]shell-help['"]\)/);
});

test('mobile viewport has no legacy outer-page overflow or focus-scroll jump', async () => {
  const css = await read('app/shell.css');
  const shell = await read('app/shell-ui.js');
  assert.match(css, /\.app-shell\{[^}]*padding:\s*8px\s+0\s+0/);
  assert.match(css, /100dvh/);
  assert.match(css, /@media\(max-width:720px\)[\s\S]*\.app-shell\{[^}]*padding:\s*4px\s+0\s+0/);
  assert.match(shell, /focus\(\{\s*preventScroll:\s*true\s*\}\)/);
  assert.doesNotMatch(shell, /\binput\.focus\(\);/);
});

test('mobile prompt is a terminal line, not a focus rectangle', async () => {
  const css = await read('app/shell.css');
  assert.match(css, /\.shell-input:focus-visible\{[^}]*outline:\s*(?:0|none)/);
  assert.match(css, /\.shell-input:focus-visible\{[^}]*outline-offset:\s*0/);
});

test('Pepe signature remains a boot-only artifact with no runtime preformatted copy', async () => {
  const entry = await read('app/terminal-entry.js');
  assert.match(entry, /pepe\.hidden = false/);
  assert.doesNotMatch(entry, /shell-boot-pepe|restorePepeSignature|pepeSignature/);
  assert.doesNotMatch(entry, /bootTranscript/);
});

test('active terminal presentation exposes the analyst@para11ax shell identity', async () => {
  const boot = await read('app/boot.js');
  const deck = await read('app/analyst-deck.js');
  const shell = await read('app/shell-ui.js');
  const commands = await read('app/shell.js');
  const active = `${boot}\n${deck}\n${shell}\n${commands}`;
  assert.match(active, /Gateway Terminal/);
  assert.match(deck, /analyst@para11ax:~\$/);
  assert.doesNotMatch(deck, /PROMPT_TEXT\s*=\s*['"](?:user@para11ax|para11ax@gateway)/);
  assert.doesNotMatch(active, /replay the Unix boot sequence|EVIDENCE TERMINAL/);
});

test('boot globe remains centered when reduced motion disables rotation', async () => {
  const entry = await read('app/terminal-entry.js');
  const css = await read('app/shell.css');
  assert.match(entry, /boot-globe/);
  assert.match(entry, /createElementNS/);
  assert.match(css, /\.boot-globe[^}]*pointer-events:\s*none/);
  assert.match(css, /\.boot-globe[^}]*transform:\s*translate\(-50%,-50%\)\s*rotate\(0deg\)/);
  assert.match(css, /globe-spin\s+2[4-9]s\s+linear\s+infinite/);
  assert.match(css, /prefers-reduced-motion:reduce[\s\S]*\.boot-globe[^}]*animation:\s*none/);
});

test('wireframe globe is visible in standby and stays visible through boot', async () => {
  const css = await read('app/shell.css');
  const baseRule = css.match(/\.boot-globe\{([^}]*)\}/)?.[1] || '';
  const baseOpacity = Number(baseRule.match(/opacity:\s*([0-9.]+)/)?.[1]);
  assert.ok(baseOpacity > 0, 'standby globe must be visible before INITIALIZE');
  assert.match(css, /\.boot-powering \.boot-globe[^}]*opacity:/);
  assert.match(css, /\.boot-modem \.boot-globe[^}]*opacity:/);
});

test('PARA11AX semantic color scheme is canonical across boot shell and result surfaces', async () => {
  const css = await read('app/shell.css');
  assert.match(css, /--terminal-bg\s*:\s*#020403/i);
  assert.match(css, /--terminal-phosphor\s*:\s*#39ff14/i);
  assert.match(css, /--terminal-alert\s*:\s*#ff2438/i);
  assert.match(css, /--terminal-text\s*:\s*#f7fff6/i);
  assert.match(css, /--terminal-muted\s*:\s*#8da391/i);
  assert.match(css, /\.shell-cyan,.shell-green\{[^}]*var\(--terminal-phosphor\)/);
  assert.match(css, /\.shell-amber\{[^}]*var\(--terminal-muted\)/);
  assert.match(css, /\.shell-red\{[^}]*var\(--terminal-alert\)/);
  assert.doesNotMatch(css, /#00e5ff|#f6c945|#39ff88|#ff1e2d|#ff4050/i);
});

test('glitch system is event-driven and bounded to boot and meaningful terminal events', async () => {
  const entry = await read('app/terminal-entry.js');
  const shell = await read('app/shell-ui.js');
  const css = await read('app/shell.css');
  assert.match(entry, /triggerGlitch/);
  assert.match(entry, /glitch-pepe|glitch-boot|glitch-lock/);
  assert.match(shell, /glitch-scan|glitch-error|glitch-result|glitch-disconnect/);
  assert.match(css, /@keyframes\s+px-glitch-tear/);
  assert.match(css, /@keyframes\s+px-glitch-chroma/);
  assert.match(css, /\.glitch-pepe[^}]*animation/);
  assert.match(css, /\.glitch-scan[^}]*animation/);
  assert.doesNotMatch(css, /\.unix-shell\s*\{[^}]*animation:\s*[^;]*infinite/, 'active shell must not constantly glitch');
});

test('mobile glitch effects never widen the viewport', async () => {
  const css = await read('app/shell.css');
  assert.match(css, /@media\(max-width:430px\)[\s\S]*\.glitch-/);
  assert.doesNotMatch(css, /@media\(max-width:430px\)[\s\S]*\.glitch-[^{]+\{[^}]*scale\(/, 'mobile glitches must avoid scale-based overflow');
  assert.doesNotMatch(css, /@media\(max-width:430px\)[\s\S]*\.glitch-[^{]+\{[^}]*translateX\([^)]*(?:1[0-9]|[2-9]\d)px/, 'mobile glitch displacement must remain tiny');
});

test('reduced motion keeps semantic glitch feedback without animated tearing', async () => {
  const css = await read('app/shell.css');
  assert.match(css, /prefers-reduced-motion:reduce[\s\S]*\.glitch-[^{]+\{[^}]*animation:none!important/);
  assert.match(css, /prefers-reduced-motion:reduce[\s\S]*text-shadow:[^;}]*var\(--terminal-alert\)[^;}]*var\(--terminal-phosphor\)/);
});
