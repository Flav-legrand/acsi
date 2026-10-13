// IAM-Local — Pilotage minimal de Chrome/Edge headless (Chrome DevTools Protocol).
// Sans dépendance : Node >= 22 (WebSocket natif). Utilisé par
// tools/guide/captures.mjs (captures d'écran) et tools/guide/build-pdf.mjs (PDF).

import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CANDIDATES = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

export function findChrome() {
  return CANDIDATES.find((p) => existsSync(p)) ?? null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Browser {
  static async launch({ width = 1440, height = 900 } = {}) {
    const exe = findChrome();
    if (!exe) throw new Error('Chrome/Edge introuvable (variable CHROME_PATH pour préciser le chemin).');
    const profile = mkdtempSync(join(tmpdir(), 'iam-cdp-'));
    const port = 9300 + Math.floor(Math.random() * 500);
    const proc = spawn(exe, [
      '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
      '--no-first-run', '--no-default-browser-check', '--disable-extensions',
      `--window-size=${width},${height}`, '--hide-scrollbars', '--lang=fr-FR', 'about:blank',
    ], { stdio: 'ignore' });
    let ws;
    for (let i = 0; i < 50 && !ws; i++) {
      await sleep(200);
      try {
        const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
        const page = list.find((t) => t.type === 'page');
        if (page) ws = page.webSocketDebuggerUrl;
      } catch { /* Chrome démarre encore */ }
    }
    if (!ws) { proc.kill(); throw new Error('Chrome headless ne répond pas.'); }
    const b = new Browser(proc, profile, ws);
    await b.open();
    await b.send('Page.enable');
    await b.send('Runtime.enable');
    await b.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    return b;
  }

  constructor(proc, profile, wsUrl) {
    Object.assign(this, { proc, profile, wsUrl, id: 0, pending: new Map(), listeners: [] });
  }

  open() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.addEventListener('open', () => resolve());
      this.ws.addEventListener('error', (e) => reject(e));
      this.ws.addEventListener('message', (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.id && this.pending.has(msg.id)) {
          const { res, rej } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
        } else if (msg.method) {
          this.listeners = this.listeners.filter((l) => !(l.method === msg.method && l.fn(msg.params)));
        }
      });
    });
  }

  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => this.pending.set(id, { res, rej }));
  }

  waitEvent(method, timeout = 15000) {
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(null), timeout);
      this.listeners.push({ method, fn: (p) => { clearTimeout(t); resolve(p); return true; } });
    });
  }

  async goto(url) {
    const loaded = this.waitEvent('Page.loadEventFired');
    await this.send('Page.navigate', { url });
    await loaded;
    await sleep(300);
  }

  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`JS : ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  }

  /** Exécute du JS qui déclenche une navigation (soumission de formulaire, clic). */
  async evalAndWait(expression) {
    const loaded = this.waitEvent('Page.loadEventFired');
    await this.eval(expression);
    await loaded;
    await sleep(300);
  }

  async url() {
    return this.eval('location.href');
  }

  async screenshot(path) {
    const { data } = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    writeFileSync(path, Buffer.from(data, 'base64'));
  }

  async pdf(path, options) {
    const { data } = await this.send('Page.printToPDF', options);
    writeFileSync(path, Buffer.from(data, 'base64'));
  }

  async close() {
    try { await this.send('Browser.close'); } catch { /* déjà fermé */ }
    this.proc.kill();
    await sleep(300);
    try { rmSync(this.profile, { recursive: true, force: true }); } catch { /* verrou Windows */ }
  }
}
