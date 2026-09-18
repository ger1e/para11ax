import { GatewayHttpError } from './api-client.js';
import { createHistory } from './shell.js';
import { COMMAND_REGISTRY } from './shell-core/catalog.js';
import { completeShellInput } from './shell-core/completion.js';
import { parseShellLine } from './shell-core/parser.js';
import { executePipeline } from './shell-core/runtime.js';
import { createBrowserShellExecutor } from './shell-browser-executor.js';
import { caseShellAdapter } from './case-shell-bridge.js';
import { investigationShellAdapter } from './investigation-shell-bridge.js';
import { createMissionFileSelector } from './mission-file-bridge.js';
import {
  buildOverview,
  buildEvidence,
  buildCorrelation,
  buildRelationships,
  buildCoverage,
  jsonLines,
  toFactRows,
} from './view-model.js';
import {
  renderOverview,
  renderEvidence,
  renderCorrelation,
  renderRelationships,
  renderCoverage,
  renderFacts,
  renderBrief,
  renderRaw,
} from './renderers.js';

const CONTROL_LABELS = Object.freeze(['Ctrl+L', 'Ctrl+C', 'Ctrl+U', 'Ctrl+W', 'Home', 'End', 'Escape']);
void CONTROL_LABELS;

const PALETTE_TEXT = [
  'void       #050608  terminal background',
  'phosphor   #39FF88  primary terminal signal',
  'white      #F3F7FA  primary terminal text',
  'muted      #7D8B95  secondary terminal text',
  'red        #FF1E2D  failure / contradiction / scanner',
].join('\n');

function safeFilename(indicator, suffix) {
  const stem = String(indicator || 'indicator').replace(/[^a-z0-9._-]+/gi, '_').slice(0, 80) || 'indicator';
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

function resultTone(result) {
  if (result?.status === 'ok') return 'green';
  if (result?.status === 'partial') return 'amber';
  return 'red';
}

export function mountAnalystShell({
  container,
  client,
  session,
  audio,
  version = '2.0.0',
  now = () => new Date(),
  monotonicNow = () => performance.now(),
  onReboot = () => {},
  missionFiles = null,
} = {}) {
  if (!container || !client || !session || !audio) throw new TypeError('shell dependencies required');

  const history = createHistory(200);
  let activeController = null;
  let secretMode = false;
  let busy = false;
  let glitchTimer = null;
  let browserExecutor = null;

  const root = document.createElement('section');
  root.className = 'unix-shell';
  root.setAttribute('role', 'region');
  root.setAttribute('aria-label', 'PARA11AX interactive analyst shell');

  const status = document.createElement('header');
  status.className = 'shell-status';
  const brand = document.createElement('span');
  brand.className = 'shell-brand';
  brand.textContent = `PARA11AX Gateway Terminal ${version}`;
  const sessionState = document.createElement('span');
  sessionState.className = 'shell-session-state';
  status.append(brand, sessionState);

  const scrollback = document.createElement('div');
  scrollback.className = 'shell-scrollback';
  scrollback.setAttribute('role', 'log');
  scrollback.setAttribute('aria-live', 'polite');
  scrollback.setAttribute('aria-relevant', 'additions');

  const prompt = document.createElement('form');
  prompt.className = 'shell-prompt';
  prompt.autocomplete = 'off';
  const promptLabel = document.createElement('label');
  promptLabel.className = 'shell-prompt-label';
  const input = document.createElement('input');
  input.className = 'shell-input';
  input.autocomplete = 'off';
  input.autocapitalize = 'off';
  input.spellcheck = false;
  input.enterKeyHint = 'send';
  input.setAttribute('aria-label', 'PARA11AX command line');
  promptLabel.htmlFor = 'para11ax-command-input';
  input.id = 'para11ax-command-input';
  prompt.append(promptLabel, input);

  root.append(status, scrollback, prompt);
  container.replaceChildren(root);
  container.hidden = false;

  const focusInput = () => input.focus({ preventScroll: true });
  const scrollBottom = () => { scrollback.scrollTop = scrollback.scrollHeight; };
  const appendLine = (text = '', tone = '') => {
    const line = document.createElement('div');
    line.className = `shell-line${tone ? ` shell-${tone}` : ''}`;
    line.textContent = String(text);
    scrollback.append(line);
    scrollBottom();
    return line;
  };
  const appendPre = (text, tone = '') => {
    const pre = document.createElement('pre');
    pre.className = `shell-pre${tone ? ` shell-${tone}` : ''}`;
    pre.textContent = String(text);
    scrollback.append(pre);
    scrollBottom();
    return pre;
  };
  const appendJson = (value, tone = '') => appendPre(JSON.stringify(value, null, 2), tone);
  const clearScrollback = () => scrollback.replaceChildren();

  const appendStructuredFacts = (title, value, tone = '') => {
    const block = document.createElement('section');
    block.className = `shell-result shell-result-facts${tone ? ` shell-${tone}` : ''}`;
    scrollback.append(block);
    renderFacts(block, title, toFactRows(value, { limit: 64 }), tone);
    scrollBottom();
    return block;
  };

  const renderRecordCollection = (title, values, tone = '') => {
    const records = Array.isArray(values) ? values : [];
    if (!records.length) {
      appendStructuredFacts(title, { state: 'none' }, tone);
      return;
    }
    const block = document.createElement('section');
    block.className = `shell-result shell-result-facts${tone ? ` shell-${tone}` : ''}`;
    scrollback.append(block);
    const heading = document.createElement('div');
    heading.className = 'shell-fact-heading';
    heading.textContent = title;
    block.append(heading);
    for (const [index, value] of records.slice(0, 100).entries()) {
      const child = document.createElement('section');
      renderFacts(child, `${title} ${String(index + 1).padStart(2, '0')}`, toFactRows(value, { limit: 48 }), tone);
      block.append(child);
    }
    scrollBottom();
  };

  const triggerGlitch = (className, duration = 220) => {
    if (glitchTimer) clearTimeout(glitchTimer);
    root.classList.remove(className);
    void root.offsetWidth;
    root.classList.add(className);
    try { audio.play('glitch'); } catch {}
    glitchTimer = setTimeout(() => {
      root.classList.remove(className);
      glitchTimer = null;
    }, duration);
  };

  const authenticated = () => {
    const snapshot = session.snapshot();
    return ['ready', 'result', 'running'].includes(snapshot.mode) && snapshot.hasToken;
  };

  const executorState = () => browserExecutor?.state?.() ?? { profile: 'standard', currentResult: null };
  const updateStatus = () => {
    const profile = executorState().profile || 'standard';
    const investigation = executorState().investigation;
    const activeInvestigation = investigation?.activeInvestigationId
      ? ` · INV:${String(investigation.activeInvestigationId).slice(0, 12)}${investigation.phase ? ` · ${investigation.phase}` : ''}`
      : '';
    sessionState.textContent = `${authenticated() ? 'AUTH:UP' : 'AUTH:DOWN'} · PROFILE:${String(profile).toUpperCase()} · ${busy ? 'BUSY' : 'READY'}${activeInvestigation}`;
    sessionState.classList.toggle('is-authenticated', authenticated());
  };
  const updatePrompt = () => {
    if (secretMode) {
      promptLabel.textContent = 'BEARER:';
      input.type = 'password';
      input.setAttribute('aria-label', 'Gateway bearer secret');
    } else {
      promptLabel.textContent = 'analyst@para11ax:~$';
      input.type = 'text';
      input.setAttribute('aria-label', 'PARA11AX command line');
    }
    updateStatus();
  };

  function renderResultView(viewName, result = executorState().currentResult) {
    if (!result) { appendLine('para11ax: no enrichment result loaded', 'amber'); return; }
    const block = document.createElement('section');
    block.className = `shell-result shell-result-${viewName}`;
    scrollback.append(block);
    if (viewName === 'brief') renderBrief(block, {
      overview: buildOverview(result),
      evidence: buildEvidence(result),
      correlation: buildCorrelation(result),
      relationships: buildRelationships(result),
      coverage: buildCoverage(result),
    });
    else if (viewName === 'overview') renderOverview(block, buildOverview(result));
    else if (viewName === 'evidence') renderEvidence(block, buildEvidence(result));
    else if (viewName === 'correlation') renderCorrelation(block, buildCorrelation(result));
    else if (viewName === 'relationships') renderRelationships(block, buildRelationships(result));
    else if (viewName === 'coverage') renderCoverage(block, buildCoverage(result));
    else renderRaw(block, jsonLines(result), '');
    scrollBottom();
  }

  const resolveStage = stage => stage ? COMMAND_REGISTRY.resolve(stage.tokens, 'web') : null;
  const finalResolution = ast => resolveStage(ast?.stages?.at(-1));
  const pipelineResolutions = ast => ast.stages.map(resolveStage).filter(Boolean);

  function renderTypedShellValue(output, ast) {
    if (!output || output.type === 'void') return;
    const final = finalResolution(ast);
    const id = final?.descriptor?.id || '';
    const args = final?.args || [];
    const invokedRoot = String(ast?.stages?.at(-1)?.tokens?.[0] || '').toLowerCase();

    if (id === 'terminal.clear' || id === 'session.login' || id === 'session.reboot') return;
    if (id === 'terminal.theme') { appendPre(PALETTE_TEXT); return; }
    if (id === 'session.disconnect') {
      try { audio.play('disconnect'); } catch {}
      triggerGlitch('glitch-disconnect', 360);
      appendLine('Connection to gateway closed.', 'amber');
      return;
    }
    if (id === 'session.auth-clear') {
      appendLine('[ OK ] volatile authentication cleared', 'green');
      return;
    }
    if (id === 'export.copy') {
      try { audio.play('copy'); } catch {}
      appendLine(`[ OK ] copied ${args[0] || 'observable'}`, 'green');
      return;
    }
    if (id === 'export.json' && args[0] === 'save') {
      appendLine('[ OK ] Evidence v2 JSON exported', 'green');
      return;
    }
    if (id === 'export.stix' && output.type === 'artifact') {
      const result = executorState().currentResult;
      downloadText(JSON.stringify(output.value, null, 2), 'application/stix+json', safeFilename(result?.indicator, 'stix.json'));
      try { audio.play('stix-ok'); } catch {}
      appendLine(`[ OK ] STIX 2.1 bundle exported · ${output.value?.objects?.length ?? 0} objects`, 'green');
      return;
    }
    if (id === 'result.raw') { renderResultView('raw', output.value); return; }
    if (id === 'result.view') {
      const view = String(args[0] || 'overview');
      renderResultView(view === 'raw' ? 'raw' : view);
      return;
    }
    if (id === 'result.summary') {
      renderResultView(invokedRoot === 'last' ? 'brief' : 'overview');
      return;
    }
    if (id === 'result.evidence') { renderResultView('evidence'); return; }
    if (id === 'result.relationships') { renderResultView('relationships'); return; }
    if (id === 'result.coverage') { renderResultView('coverage'); return; }
    if (id === 'result.correlation') { renderResultView('correlation'); return; }

    if (output.type === 'enrichment') {
      const tone = resultTone(output.value);
      appendLine(`[ ${String(output.value?.status || 'result').toUpperCase()} ] ${output.value?.indicator || ''} · ${output.value?.type || ''} · ${output.value?.durationMs ?? '?'}ms`, tone);
      renderResultView('brief', output.value);
      return;
    }
    if (output.type === 'text') {
      const value = String(output.value ?? '');
      if (!value) return;
      if (value.includes('\n')) appendPre(value);
      else appendLine(value);
      return;
    }
    if (output.type === 'scalar') { appendLine(String(output.value ?? '')); return; }
    if (['records', 'evidence', 'relationships', 'provider-list'].includes(output.type)) {
      renderRecordCollection((final?.descriptor?.usage || output.type).toUpperCase(), output.value);
      return;
    }
    if (output.type === 'artifact') {
      appendStructuredFacts('ARTIFACT', output.value ?? {}, 'green');
      return;
    }
    appendStructuredFacts((final?.descriptor?.usage || output.type).toUpperCase(), output.value ?? {});
  }

  const beginOperation = () => {
    if (busy) throw new Error('operation already active');
    activeController = new AbortController();
    busy = true;
    updateStatus();
    return activeController;
  };

  const finishTrackedSession = tracked => {
    if (!tracked || session.snapshot().mode !== 'running') return;
    const result = executorState().currentResult;
    if (result) session.finishRequest(result);
    else session.failRequest();
  };

  const endOperation = () => {
    activeController = null;
    busy = false;
    updateStatus();
  };

  const abortOperation = () => {
    if (activeController && !activeController.signal.aborted) activeController.abort();
    try { session.abortActive(); } catch {}
    activeController = null;
    busy = false;
    updateStatus();
  };

  browserExecutor = createBrowserShellExecutor({
    client,
    session,
    cases: caseShellAdapter,
    investigations: investigationShellAdapter,
    history,
    ui: {
      requestLogin() {
        if (authenticated()) {
          appendLine('authentication already active; run auth clear first', 'amber');
          return;
        }
        secretMode = true;
        updatePrompt();
        appendLine('enter gateway bearer in hidden prompt; value is memory-only and never added to history', 'muted');
      },
      clear: clearScrollback,
      async reboot() {
        triggerGlitch('glitch-disconnect', 360);
        await Promise.resolve(onReboot());
      },
    },
    downloads: { save: downloadText },
    missionFiles: missionFiles ?? createMissionFileSelector({ documentRef: container.ownerDocument ?? document }),
    clipboard: { writeText: value => navigator.clipboard.writeText(String(value)) },
    audio,
    now,
    monotonicNow,
    version,
  });

  async function runPipeline(ast) {
    const resolved = pipelineResolutions(ast);
    const hasEgress = resolved.some(item => item.descriptor.egressClass !== 'none');
    const tracksResult = resolved.some(item => item.descriptor.outputType === 'enrichment' && item.descriptor.egressClass !== 'none');
    const controller = beginOperation();

    if (hasEgress) {
      try { audio.play('scan'); } catch {}
      triggerGlitch('glitch-scan', 240);
    }
    if (tracksResult && authenticated()) session.startRequest(controller);
    if (resolved.some(item => item.descriptor.id === 'export.stix')) {
      try { audio.play('stix-start'); } catch {}
    }

    try {
      const output = await executePipeline(ast, {
        registry: COMMAND_REGISTRY,
        executor: browserExecutor,
        context: {
          surface: 'web',
          authenticated: authenticated(),
          capabilities: new Set(['gateway-read', 'provider-read']),
        },
        signal: controller.signal,
      });
      finishTrackedSession(tracksResult);
      if (output?.type === 'enrichment') {
        const result = output.value;
        try { audio.play(result?.status === 'ok' ? 'result-ok' : result?.status === 'partial' ? 'result-partial' : 'result-error'); } catch {}
        const contradictions = result?.correlation?.contradictions?.length || 0;
        triggerGlitch(contradictions || result?.status === 'error' ? 'glitch-error' : 'glitch-result', 240);
      } else if (hasEgress) triggerGlitch('glitch-result', 200);
      return output;
    } catch (error) {
      if (tracksResult && session.snapshot().mode === 'running') session.failRequest();
      throw error;
    } finally {
      endOperation();
    }
  }

  async function submitSecret() {
    const secret = input.value;
    input.value = '';
    if (!secret.trim()) { appendLine('empty bearer rejected', 'red'); triggerGlitch('glitch-error', 180); return; }
    try { await audio.enable(); } catch {}
    session.setToken(secret);
    try {
      const health = await client.health();
      session.unlock();
      secretMode = false;
      try { audio.play('access-ok'); } catch {}
      appendLine(`[  OK  ] Authentication accepted. Gateway ${health?.version || 'online'}.`, 'green');
      triggerGlitch('glitch-result', 180);
    } catch (error) {
      session.disconnect();
      secretMode = false;
      try { audio.play('access-denied'); } catch {}
      triggerGlitch('glitch-error', 260);
      appendLine(error instanceof GatewayHttpError && error.status === 401 ? '[FAILED] Authentication rejected.' : '[FAILED] Gateway unavailable.', 'red');
    } finally {
      updatePrompt();
      focusInput();
    }
  }

  prompt.addEventListener('submit', async event => {
    event.preventDefault();
    audio.typing(secretMode ? 'token' : 'enter');
    if (secretMode) { await submitSecret(); return; }

    const line = input.value;
    input.value = '';
    if (!line.trim()) { updatePrompt(); focusInput(); return; }
    history.push(line);
    appendLine(`analyst@para11ax:~$ ${line}`);

    try {
      const ast = parseShellLine(line);
      const output = await runPipeline(ast);
      renderTypedShellValue(output, ast);
    } catch (error) {
      if (error?.code === 'OPERATION_ABORTED' || error?.name === 'AbortError') appendLine('^C', 'amber');
      else {
        appendLine(`terminal: ${error?.code || 'COMMAND_FAILED'}${error?.message ? ` // ${error.message}` : ''}`, 'red');
        if (error?.code === 'COMMAND_NOT_FOUND') appendLine("type 'help' for available commands", 'muted');
        try { audio.play('result-error'); } catch {}
        triggerGlitch('glitch-error', 240);
      }
      if (busy) abortOperation();
    }
    updatePrompt();
    focusInput();
  });

  input.addEventListener('beforeinput', event => {
    if (!secretMode && event.inputType === 'insertText' && event.data) audio.typing('character');
  });
  input.addEventListener('paste', () => { if (!secretMode) audio.typing('paste'); });
  input.addEventListener('keydown', event => {
    if (secretMode) return;
    if (event.key === 'Backspace' || event.key === 'Delete') audio.typing('backspace');
    if (event.key === 'ArrowUp') { event.preventDefault(); input.value = history.up(); input.setSelectionRange(input.value.length, input.value.length); return; }
    if (event.key === 'ArrowDown') { event.preventDefault(); input.value = history.down(); input.setSelectionRange(input.value.length, input.value.length); return; }
    if (event.key === 'Tab') {
      event.preventDefault();
      const suggestions = completeShellInput(input.value, { surface: 'web' });
      if (suggestions.length === 1) {
        input.value = suggestions[0].endsWith(' ') ? suggestions[0] : `${suggestions[0]} `;
        input.setSelectionRange(input.value.length, input.value.length);
      } else if (suggestions.length > 1) appendLine(suggestions.join('  '), 'cyan');
      try { audio.play('tab'); } catch {}
      return;
    }
    if (event.ctrlKey && event.key.toLowerCase() === 'l') { event.preventDefault(); clearScrollback(); return; } // Ctrl+L
    if (event.ctrlKey && event.key.toLowerCase() === 'c') { event.preventDefault(); abortOperation(); input.value = ''; appendLine('^C', 'amber'); return; } // Ctrl+C
    if (event.ctrlKey && event.key.toLowerCase() === 'u') { event.preventDefault(); input.value = ''; return; } // Ctrl+U
    if (event.ctrlKey && event.key.toLowerCase() === 'w') { event.preventDefault(); input.value = input.value.replace(/\s*\S+\s*$/, ''); return; } // Ctrl+W
    if (event.key === 'Home') { event.preventDefault(); input.setSelectionRange(0, 0); return; }
    if (event.key === 'End') { event.preventDefault(); input.setSelectionRange(input.value.length, input.value.length); return; }
    if (event.key === 'Escape') { event.preventDefault(); input.value = ''; }
  });

  appendLine(`PARA11AX Gateway Terminal ${version}`);
  appendLine('CTI Enrichment // session unauthenticated', 'muted');
  appendLine("type 'help' for commands; run 'login' to authenticate", 'cyan');
  updatePrompt();
  focusInput();

  return Object.freeze({
    focus: focusInput,
    clear: clearScrollback,
    abort: () => {
      if (glitchTimer) clearTimeout(glitchTimer);
      abortOperation();
    },
    state: () => Object.freeze({
      authenticated: authenticated(),
      profile: executorState().profile,
      hasResult: Boolean(executorState().currentResult),
      busy,
      secretMode,
    }),
  });
}
