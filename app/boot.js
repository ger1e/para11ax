import { MODEM_HANDSHAKE_MS } from './audio.js';

export const PEPE_HOLD_MS = 1900;

export const PARA11AX_BOOT_LINES = Object.freeze([
  '[    0.000000] PARA11AX kernel 2.0.0 booting',
  '[    0.018442] random: entropy pool initialized [ OK ]',
  '[    0.027913] memory: volatile analyst workspace online [ OK ]',
  '[    0.041207] terminal0: framebuffer initialized [ OK ]',
  '[    0.058991] input0: keyboard controller attached [ OK ]',
  '[    0.071552] audio0: synthesized terminal device detected [ OK ]',
  '[    0.088440] net0: fixed-egress interface registered [ OK ]',
  '[    0.104811] net0: route policy locked [ OK ]',
  '[    0.128337] cache0: bounded TTL cache interface ready [ OK ]',
  '[    0.155002] pxsvc[evidence-v2]: schema loaded [ OK ]',
  '[    0.173449] pxsvc[provenance]: integrity fingerprints enabled [ OK ]',
  '[    0.196721] pxsvc[semantic-firewall]: absence != benign [ OK ]',
  '[    0.217208] pxsvc[semantic-firewall]: context != reputation [ OK ]',
  '[    0.238901] pxsvc[semantic-firewall]: claims != compromise proof [ OK ]',
  '[    0.259514] pxsvc[semantic-firewall]: infrastructure != attribution [ OK ]',
  '[    0.282113] pxsvc[correlation]: corroboration pipeline ready [ OK ]',
  '[    0.304848] pxsvc[correlation]: contradictions pipeline ready [ OK ]',
  '[    0.329991] pxsvc[relationships]: deduplication enabled [ OK ]',
  '[    0.354108] pxsvc[huntability]: bounded analyst pivots enabled [ OK ]',
  '[    0.377771] pxsvc[risk-axis]: KEV isolated [ OK ]',
  '[    0.397421] pxsvc[risk-axis]: EPSS isolated [ OK ]',
  '[    0.416994] pxsvc[risk-axis]: CVSS isolated [ OK ]',
  '[    0.441862] pxsvc[stix-2.1]: serializer ready [ OK ]',
  '[    0.468220] pxsvc[export]: JSON channel ready [ OK ]',
  '[    0.489668] pxsvc[provider-registry]: 39 sources registered [ OK ]',
  '[    0.512990] pxsvc[provider-registry]: arbitrary override disabled [ OK ]',
  '[    0.538221] pxsvc[active-scan]: disabled by policy [ OK ]',
  '[    0.563114] pxsvc[auth]: bearer storage volatile [ OK ]',
  '[    0.588443] pxsvc[auth]: persistent credential storage disabled [ OK ]',
  '[    0.614008] pxsvc[shell]: command allowlist loaded [ OK ]',
  '[    0.639872] pxsvc[shell]: history secret filter active [ OK ]',
  '[    0.667004] pxsvc[shell]: completion index built [ OK ]',
  '[    0.694771] pxsvc[field-ui]: mobile terminal layout ready [ OK ]',
  '[    0.724219] pxsvc[gateway]: analyst shell bound [ OK ]',
  '[    0.751662] pxsvc[gateway]: Gateway Terminal active [ OK ]',
]);

export function createPara11axBootSequence({
  audio,
  reducedMotion = false,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  onStage = () => {},
} = {}) {
  let started = false;
  let done = false;
  let skipped = false;

  const safeEnable = () => {
    try { void Promise.resolve(audio?.enable?.()).catch(() => {}); } catch {}
  };
  const safePlay = name => { try { audio?.play?.(name); } catch {} };
  const safeStop = () => { try { audio?.stopAll?.(); } catch {} };
  const wait = async ms => { await sleep(ms); return !done; };

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
      safeEnable();
      if (reducedMotion) onStage('reduced');

      onStage('power');
      safePlay('boot-power');
      if (!await wait(280)) return true;

      onStage('modem');
      safePlay('modem-56k');
      if (!await wait(MODEM_HANDSHAKE_MS)) return true;

      for (let index = 0; index < PARA11AX_BOOT_LINES.length; index += 1) {
        onStage('boot-line', PARA11AX_BOOT_LINES[index]);
        const pause = [4, 9, 15, 24, 29].includes(index) ? 110 : 34;
        if (!await wait(pause)) return true;
      }

      onStage('pepe');
      safePlay('boot-lock');
      if (!await wait(PEPE_HOLD_MS)) return true;

      onStage('target', '[  OK  ] PARA11AX services online // Gateway Terminal ready.');
      if (!await wait(420)) return true;
      ready();
      return true;
    },
    async skip() {
      if (done) return false;
      if (!started) {
        started = true;
        safeEnable();
      }
      safeStop();
      skipped = true;
      ready();
      return true;
    },
    state() { return Object.freeze({ started, done, skipped }); },
  });
}
