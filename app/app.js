import { createGatewayClient, GatewayHttpError } from './api-client.js';
import { createSession } from './session.js';
import { createAudioEngine } from './audio.js';
import {
  buildOverview,
  buildEvidence,
  buildCorrelation,
  buildRelationships,
  buildCoverage,
  jsonLines,
} from './view-model.js';
import {
  clear,
  renderOverview,
  renderEvidence,
  renderCorrelation,
  renderRelationships,
  renderCoverage,
  renderRaw,
} from './renderers.js';

export const VIEWS = Object.freeze(['overview', 'evidence', 'correlation', 'relationships', 'coverage', 'raw']);
export const POST_LINES = Object.freeze([
  'MEMORY BUS........................................ [ OK ]',
  'DISPLAY PIPELINE................................. [ OK ]',
  'AUDIO SYNTH...................................... [ OK ]',
  'INPUT CONTROLLER................................. [ OK ]',
  'TERMINAL RENDERER................................ [ OK ]',
  'EVIDENCE MODEL v2................................ [ OK ]',
  'SEMANTIC FIREWALL................................ [ OK ]',
  'CORRELATION ENGINE............................... [ OK ]',
  'RELATIONSHIP INDEX............................... [ OK ]',
  'PROVENANCE TRACKER............................... [ OK ]',
  'INTEGRITY FINGERPRINTS........................... [ OK ]',
  'CACHE STATE PARSER............................... [ OK ]',
  'FAILURE ISOLATION................................ [ OK ]',
  'CONTRADICTION ENGINE............................. [ OK ]',
  'HUNTABILITY MODEL................................ [ OK ]',
  'RAW JSON VIEW.................................... [ OK ]',
  'STIX 2.1 SERIALIZER.............................. [ OK ]',
  'EXPORT CONTROLLER................................ [ OK ]',
  'CLIPBOARD INTERFACE.............................. [ OK ]',
  'SESSION MEMORY................................... [ OK ]',
  'BEARER STORAGE................................... [ VOLATILE ]',
  'PERSISTENT AUTH STORAGE.......................... [ OFF ]',
  'THIRD-PARTY RUNTIME.............................. [ NONE ]',
  'FIXED PROFILE TABLE.............................. [ OK ]',
  'FIXED EGRESS POLICY.............................. [ LOADED ]',
  'PROVIDER OVERRIDE................................ [ DISABLED ]',
  'ACTIVE SCANNING.................................. [ DISABLED ]',
  'TELEMETRY LEAKAGE GUARD.......................... [ OK ]',
  'REDUCED MOTION................................... [ READY ]',
  'MOBILE TERMINAL.................................. [ OK ]',
  'AUDIO CHANNEL.................................... [ ARMED ]',
  'LOCAL MODULE SELF-TEST........................... [ PASS ]',
  'PARA11AX TERMINAL................................ [ READY ]',
]);
export const serializeJson = (value) => JSON.stringify(value, null, 2);

export function createBootSequence({
  audio,
  reducedMotion = false,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  onStage = () => {},
} = {}) {
  let started = false;
  let done = false;
  let skipped = false;

  const wait = async (ms) => {
    await sleep(ms);
    return !done;
  };
  const safeEnable = async () => {
    try { await audio?.enable?.(); } catch {}
  };
  const safePlay = (name) => {
    try { audio?.play?.(name); } catch {}
  };
  const safeStop = () => {
    try { audio?.stopAll?.(); } catch {}
  };

  const ready = () => {
    if (done) return;
    onStage('ready');
    safePlay('boot-ready');
    done = true;
  };

  return Object.freeze({
    async start() {
      if (started || done) return false;
      started = true;
      void safeEnable(); // Audio must never gate terminal initialization.

      if (reducedMotion) {
        onStage('reduced');
        await sleep(300);
        ready();
        return true;
      }

      onStage('power');
      safePlay('boot-power');
      if (!await wait(320)) return true;

      onStage('modem');
      safePlay('modem-56k');
      if (!await wait(3200)) return true;

      onStage('pepe');
      safePlay('boot-lock');
      if (!await wait(650)) return true;

      for (let index = 0; index < POST_LINES.length; index += 1) {
        onStage('post-line', POST_LINES[index]);
        const groupPause = index === 4 || index === 9 || index === 15 || index === 23 || index === 29;
        if (!await wait(groupPause ? 115 : 32)) return true;
      }

      onStage('scanner');
      if (!await wait(360)) return true;
      ready();
      return true;
    },
    async skip() {
      if (done) return false;
      if (!started) {
        started = true;
        void safeEnable();
      }
      safeStop();
      skipped = true;
      ready();
      return true;
    },
    state() {
      return Object.freeze({ started, done, skipped });
    },
  });
}

function safeFilename(indicator, suffix) {
  const stem = String(indicator || 'indicator')
    .replace(/[^a-z0-9._-]+/gi, '_')
    .slice(0, 80) || 'indicator';
  return `${stem}.${suffix}`;
}

function downloadText(text, type, filename) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  queueMicrotask(() => URL.revokeObjectURL(url));
}

async function copyText(value) {
  await navigator.clipboard.writeText(String(value));
}

if (typeof document !== 'undefined') bootstrap();

function bootstrap() {
  const session = createSession();
  const audio = createAudioEngine();
  const client = createGatewayClient({ getToken: session.getToken });
  const byId = (id) => document.getElementById(id);

  const bootPanel = byId('boot-panel');
  const bootInitialize = byId('boot-initialize');
  const bootSkip = byId('boot-skip');
  const bootLog = byId('boot-log');
  const pepeAscii = byId('pepe-ascii');
  const bootStatus = byId('boot-status');
  const accessPanel = byId('access-panel');
  const accessForm = byId('access-form');
  const tokenInput = byId('token');
  const workspace = byId('workspace');
  const pivotForm = byId('terminal-input-line');
  const indicatorInput = byId('indicator');
  const profile = byId('profile');
  const enrichButton = byId('enrich');
  const disconnectButton = byId('disconnect');
  const hud = byId('result-status');
  const tabs = byId('tabs');
  const actions = byId('result-actions');
  const view = byId('view');
  const live = byId('live-status');
  const rawSearch = byId('raw-search');
  const rawSearchLabel = byId('raw-search-label');
  const stixButton = byId('download-stix');
  const resetButton = byId('reset');

  let activeView = 'overview';
  let currentResult = null;
  let contradictionCueRequestId = null;
  let operationController = null;
  let busy = false;
  let accessRevealed = false;

  const announce = (text) => { live.textContent = text; };
  const setLocked = (locked) => {
    accessPanel.hidden = !locked;
    workspace.hidden = locked;
  };

  function revealAccess() {
    if (accessRevealed) return;
    accessRevealed = true;
    accessPanel.hidden = false;
    document.body.classList.remove('boot-powering', 'boot-modem', 'boot-pepe-visible', 'boot-glitch', 'boot-posting', 'boot-scanning');
    document.body.classList.add('boot-complete');
    tokenInput.focus();
    accessPanel.scrollIntoView?.({ block: 'end' });
    announce('PARA11AX terminal ready. Analyst access waiting.');
  }

  function appendBootLine(text, className = 'boot-line') {
    const line = document.createElement('div');
    line.className = className;
    if (className.includes('boot-post-line')) {
      const match = String(text).match(/^(.*?)(\s+\[\s*([A-Z-]+)\s*\])$/);
      if (match) {
        const label = document.createElement('span');
        label.className = 'boot-post-label';
        label.textContent = match[1].trimEnd();
        const status = document.createElement('span');
        status.className = 'boot-post-status';
        const led = document.createElement('span');
        led.className = `post-led ${match[3].toLowerCase()}`;
        led.setAttribute('aria-hidden', 'true');
        const statusText = document.createElement('span');
        statusText.textContent = match[2].trim();
        status.append(led, statusText);
        line.append(label, status);
      } else {
        line.textContent = text;
      }
    } else {
      line.textContent = text;
    }
    bootLog.append(line);
    bootLog.scrollTop = bootLog.scrollHeight;
  }

  function renderBootStage(stage, payload) {
    document.body.classList.add('boot-active');
    if (stage === 'power') {
      document.body.classList.add('boot-powering');
      bootStatus.textContent = 'CRT POWER // BUS ONLINE';
      bootLog.replaceChildren();
      appendBootLine('PARA11AX BIOS 2.0.0');
      appendBootLine('COPYRIGHT 2026 // EVIDENCE TERMINAL');
      return;
    }
    if (stage === 'modem') {
      document.body.classList.remove('boot-powering');
      document.body.classList.add('boot-modem');
      bootStatus.textContent = 'DATA LINK // NEGOTIATING 56K';
      appendBootLine('ATZ');
      appendBootLine('OK');
      appendBootLine('ATDT PARA11AX-UPLINK');
      appendBootLine('CONNECT 56000/V90');
      return;
    }
    if (stage === 'pepe') {
      document.body.classList.remove('boot-modem');
      document.body.classList.add('boot-pepe-visible', 'boot-glitch');
      pepeAscii.hidden = false;
      bootStatus.textContent = 'FIRMWARE SIGNATURE // VERIFIED';
      return;
    }
    if (stage === 'post-line') {
      if (!document.body.classList.contains('boot-posting')) {
        document.body.classList.remove('boot-pepe-visible', 'boot-glitch');
        document.body.classList.add('boot-posting');
        pepeAscii.hidden = true;
        bootLog.replaceChildren();
      }
      appendBootLine(payload, 'boot-line boot-post-line');
      return;
    }
    if (stage === 'scanner') {
      document.body.classList.remove('boot-posting');
      document.body.classList.add('boot-scanning');
      bootStatus.textContent = 'LOCAL MODULE SELF-TEST // PASS';
      return;
    }
    if (stage === 'reduced') {
      pepeAscii.hidden = false;
      document.body.classList.add('boot-pepe-visible');
      bootStatus.textContent = 'PARA11AX // STATIC INITIALIZATION';
      return;
    }
    if (stage === 'ready') {
      bootStatus.textContent = 'PARA11AX TERMINAL // READY';
      document.body.classList.remove('boot-scanning');
      document.body.classList.add('boot-ready');
    }
  }

  const reducedMotion = Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
  const boot = createBootSequence({ audio, reducedMotion, onStage: renderBootStage });

  // The animation is cosmetic. Never let a stalled timer, audio promise, or
  // rendering error prevent access to the authenticated terminal.
  let bootWatchdog = null;
  const finishBoot = () => {
    if (bootWatchdog !== null) clearTimeout(bootWatchdog);
    bootWatchdog = null;
    bootInitialize.disabled = true;
    bootSkip.disabled = true;
    revealAccess();
  };
  bootInitialize.addEventListener('click', () => {
    bootInitialize.disabled = true;
    bootWatchdog = setTimeout(finishBoot, 9000);
    void boot.start().then((ran) => {
      if (ran) finishBoot();
    }).catch(finishBoot);
  });
  bootSkip.addEventListener('click', () => {
    // Skip is an emergency escape hatch, even while INITIALIZE is running.
    finishBoot();
    void boot.skip().catch(() => {});
  });

  function setBusy(value) {
    busy = Boolean(value);
    document.body.classList.toggle('is-busy', busy);
    enrichButton.disabled = busy;
    stixButton.disabled = busy;
    resetButton.disabled = busy;
    indicatorInput.disabled = busy;
    profile.disabled = busy;
  }

  function abortOperation() {
    if (operationController && !operationController.signal.aborted) operationController.abort();
    operationController = null;
  }

  function clearResult() {
    currentResult = null;
    contradictionCueRequestId = null;
    activeView = 'overview';
    clear(hud);
    clear(view);
    hud.hidden = true;
    tabs.hidden = true;
    actions.hidden = true;
    rawSearch.hidden = true;
    rawSearchLabel.hidden = true;
    rawSearch.value = '';
    updateViewCommands();
  }

  function lockSession(message) {
    abortOperation();
    setBusy(false);
    session.disconnect();
    clearResult();
    indicatorInput.value = '';
    tokenInput.value = '';
    bootPanel.hidden = true;
    setLocked(true);
    announce(message);
  }

  accessForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    await audio.enable();
    session.setToken(tokenInput.value);
    try {
      const health = await client.health();
      session.unlock();
      audio.play('access-ok');
      bootPanel.hidden = true;
      setLocked(false);
      tokenInput.value = '';
      indicatorInput.focus();
      announce(`Authentication OK. Gateway health OK${health?.version ? `, API ${health.version}` : ''}. Session established.`);
    } catch (error) {
      audio.play('access-denied');
      lockSession(error instanceof GatewayHttpError && error.status === 401 ? 'Unauthorized token.' : 'Gateway unavailable.');
    }
  });

  indicatorInput.addEventListener('keydown', (event) => {
    if (event.key === 'Backspace' || event.key === 'Delete') audio.typing('backspace');
    else if (event.key === 'Enter') audio.typing('enter');
  });
  indicatorInput.addEventListener('beforeinput', (event) => {
    if (event.inputType === 'insertText' && event.data) audio.typing('character');
  });
  indicatorInput.addEventListener('paste', () => audio.typing('paste'));

  byId('sound-toggle').addEventListener('click', () => {
    const muted = !audio.state().muted;
    audio.mute(muted);
    byId('sound-toggle').setAttribute('aria-pressed', String(!muted));
    byId('sound-toggle').textContent = muted ? 'SND:OFF' : 'SND:ON';
  });

  byId('volume').addEventListener('input', (event) => audio.setVolume(event.currentTarget.value));

  function updateViewCommands() {
    for (const button of tabs.querySelectorAll('[data-view]')) {
      const selected = button.dataset.view === activeView;
      button.setAttribute('aria-pressed', String(selected));
      button.classList.toggle('is-active', selected);
      button.disabled = !currentResult;
    }
  }

  for (const button of tabs.querySelectorAll('[data-view]')) {
    button.addEventListener('click', () => {
      if (!currentResult) return;
      activeView = button.dataset.view;
      audio.play('tab');
      updateViewCommands();
      renderActiveView();
    });
  }
  updateViewCommands();

  function renderActiveView() {
    if (!currentResult) return;
    rawSearch.hidden = activeView !== 'raw';
    rawSearchLabel.hidden = activeView !== 'raw';

    if (activeView === 'overview') return renderOverview(view, buildOverview(currentResult));
    if (activeView === 'evidence') return renderEvidence(view, buildEvidence(currentResult));
    if (activeView === 'correlation') {
      const model = buildCorrelation(currentResult);
      renderCorrelation(view, model);
      if (model.contradictions.length && contradictionCueRequestId !== currentResult.requestId) {
        audio.play('contradiction');
        contradictionCueRequestId = currentResult.requestId;
      }
      return;
    }
    if (activeView === 'relationships') return renderRelationships(view, buildRelationships(currentResult));
    if (activeView === 'coverage') return renderCoverage(view, buildCoverage(currentResult));
    renderRaw(view, jsonLines(currentResult), rawSearch.value);
  }

  rawSearch.addEventListener('input', () => {
    if (currentResult && activeView === 'raw') renderActiveView();
  });

  function renderResult() {
    activeView = 'overview';
    renderOverview(hud, buildOverview(currentResult));
    hud.hidden = false;
    tabs.hidden = false;
    actions.hidden = false;
    updateViewCommands();
    renderActiveView();
  }

  pivotForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;

    const controller = new AbortController();
    operationController = controller;
    setBusy(true);
    try {
      session.startRequest(controller);
      audio.play('scan');
      document.body.classList.add('is-scanning');
      announce('Enrichment running.');
      const result = await client.enrich(indicatorInput.value, profile.value, controller.signal);
      currentResult = result;
      session.finishRequest(result);
      operationController = null;
      renderResult();
      audio.play(result.status === 'ok' ? 'result-ok' : result.status === 'partial' ? 'result-partial' : 'result-error');
      announce(`Enrichment complete: ${result.status}.`);
    } catch (error) {
      operationController = null;
      if (error?.name === 'AbortError') return;
      if (error instanceof GatewayHttpError && error.status === 401) {
        audio.play('access-denied');
        lockSession('Session unauthorized.');
        return;
      }
      session.reset();
      audio.play('result-error');
      announce(error instanceof GatewayHttpError ? `Gateway error: ${error.code}.` : 'Request failed.');
    } finally {
      document.body.classList.remove('is-scanning');
      setBusy(false);
    }
  });

  async function copyWithCue(value, successMessage) {
    try {
      await copyText(value);
      audio.play('copy');
      announce(successMessage);
    } catch {
      announce('Clipboard access unavailable.');
    }
  }

  byId('copy-ioc').addEventListener('click', () => {
    if (currentResult) void copyWithCue(currentResult.indicator, 'Observable copied.');
  });
  byId('copy-json').addEventListener('click', () => {
    if (currentResult) void copyWithCue(serializeJson(currentResult), 'JSON copied.');
  });
  byId('download-json').addEventListener('click', () => {
    if (!currentResult) return;
    downloadText(serializeJson(currentResult), 'application/json', safeFilename(currentResult.indicator, 'evidence.json'));
    announce('Evidence JSON downloaded.');
  });

  stixButton.addEventListener('click', async () => {
    if (!currentResult || busy) return;

    const controller = new AbortController();
    operationController = controller;
    setBusy(true);
    audio.play('stix-start');
    announce('Packaging STIX 2.1.');
    try {
      const bundle = await client.stix(currentResult.indicator, currentResult.profile, controller.signal);
      operationController = null;
      downloadText(serializeJson(bundle), 'application/stix+json', safeFilename(currentResult.indicator, 'stix.json'));
      audio.play('stix-ok');
      announce('STIX 2.1 bundle downloaded.');
    } catch (error) {
      operationController = null;
      if (error?.name === 'AbortError') return;
      if (error instanceof GatewayHttpError && error.status === 401) {
        audio.play('access-denied');
        lockSession('Session unauthorized.');
        return;
      }
      audio.play('result-error');
      announce(error instanceof GatewayHttpError ? `STIX export failed: ${error.code}.` : 'STIX export failed.');
    } finally {
      setBusy(false);
    }
  });

  resetButton.addEventListener('click', () => {
    if (busy) return;
    session.reset();
    clearResult();
    indicatorInput.value = '';
    indicatorInput.focus();
    announce('Result cleared.');
  });

  disconnectButton.addEventListener('click', () => {
    audio.play('disconnect');
    lockSession('Disconnected.');
  });
}
