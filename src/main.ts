import {
    app,
    BrowserWindow,
    Menu,
    Tray,
    dialog,
    globalShortcut,
    nativeImage,
    ipcMain,
  } from "electron";
  import type { IpcMainInvokeEvent } from "electron";
  import * as fs from "fs";
  import * as path from "path";
  import * as crypto from "crypto";
  import * as net from "net";
  
  // ----------------------------
  // Types & globals
  // ----------------------------
  type Config = {
    printerIp: string;       // e.g. 192.168.1.50 or "simulate"
    printerPort: number;     // usually 9100
    drawerChannel: 0 | 1;    // try 0 first; some drawers use 1
    pulseOn: number;         // t1 (0-255) ~ on time (ms-ish)
    pulseOff: number;        // t2 (0-255) ~ off time
    pinHash?: string;        // staff PIN (SHA-256)
    adminHash?: string;      // admin PIN (SHA-256)
  };
  
  let tray: Tray | null = null;
  let settingsWin: BrowserWindow | undefined;
  
  // ----------------------------
  // Helpers
  // ----------------------------
  function resolveAsset(rel: string) {
    const candidates = [
      path.join(__dirname, "assets", rel),                  // dev (dist/assets)
      path.join(process.resourcesPath || "", "assets", rel),// packaged (Resources/assets)
      path.join(__dirname, "..", "src", "assets", rel),     // fallback to src/assets
    ];
    for (const p of candidates) if (fs.existsSync(p)) return p;
    return null;
  }
  
  function getUserDataPath() {
    return app.getPath("userData");
  }
  function configPath() {
    return path.join(getUserDataPath(), "config.json");
  }
  function sha256(text: string) {
    return crypto.createHash("sha256").update(text).digest("hex");
  }
  
  function loadConfig(): Config {
    try {
      const c = JSON.parse(fs.readFileSync(configPath(), "utf8"));
      return {
        printerIp: c.printerIp ?? "",
        printerPort: c.printerPort ?? 9100,
        drawerChannel: (c.drawerChannel === 1 ? 1 : 0),
        pulseOn: c.pulseOn ?? 50,
        pulseOff: c.pulseOff ?? 200,
        pinHash: c.pinHash,
        adminHash: c.adminHash,
      };
    } catch {
      return {
        printerIp: "",
        printerPort: 9100,
        drawerChannel: 0,
        pulseOn: 50,
        pulseOff: 200,
        pinHash: undefined,
        adminHash: undefined,
      };
    }
  }
  function saveConfig(cfg: Config) {
    fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2), "utf8");
  }
  
  // ----------------------------
  // Branded PIN modal (replaces electron-prompt)
  // ----------------------------
  async function pinPrompt(opts: {
    title: string;
    label: string;
    password?: boolean;
  }): Promise<string | null> {
    return new Promise((resolve) => {
      const channel = "pin-" + crypto.randomBytes(6).toString("hex");
  
      const win = new BrowserWindow({
        width: 520,
        height: 210,
        resizable: false,
        modal: true,
        alwaysOnTop: true,
        title: opts.title,
        parent: settingsWin, // can be undefined; Electron accepts that
        webPreferences: { nodeIntegration: true, contextIsolation: false },
      });
  
      const logoFile = resolveAsset("bond_logo.png");
      const logoSrc = logoFile
        ? `data:image/png;base64,${fs.readFileSync(logoFile).toString("base64")}`
        : "";
      const inputType = opts.password ? "password" : "text";
  
      const html = `
        <html><head><meta charset="utf-8"/>
          <style>
            :root { --navy:#0e4a6b; --muted:#6b7280; --bg:#f5f7fa; }
            *{box-sizing:border-box}
            body { margin:0; background:var(--bg); font-family:-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
            .wrap{padding:18px 20px;}
            .head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
            .head img{width:70px;height:24px;border-radius:6px;background:#fff}
            h3{margin:0;color:#111827;font-size:16px;font-weight:700}
            label{display:block;margin:10px 0 8px;color:var(--navy);font-weight:600;font-size:16px}
            input{width:100%;padding:10px 12px;border:1px solid #e5e7eb;border-radius:10px;font-size:16px;outline:none}
            input:focus{border-color:var(--navy);box-shadow:0 0 0 3px rgba(14,74,107,.12)}
            .actions{display:flex;justify-content:flex-end;gap:10px;margin-top:14px}
            button{border:none;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer}
            .sec{background:#eef2f7;color:#0b3d57}
            .pri{background:var(--navy);color:#fff}
          </style>
        </head>
        <body>
          <div class="wrap">
            <div class="head">${logoSrc ? `<img src="${logoSrc}"/>` : ""}<h3>${opts.title}</h3></div>
            <label>${opts.label}</label>
            <input id="inp" type="${inputType}" autofocus />
            <div class="actions">
              <button class="sec" id="cancel">Cancel</button>
              <button class="pri" id="ok">OK</button>
            </div>
          </div>
          <script>
            const { ipcRenderer } = require('electron');
            const chan = ${JSON.stringify(channel)};
            const ok = () => ipcRenderer.send(chan, { ok: true, value: document.getElementById('inp').value });
            const cancel = () => ipcRenderer.send(chan, { ok: false });
            document.getElementById('ok').onclick = ok;
            document.getElementById('cancel').onclick = cancel;
            document.getElementById('inp').addEventListener('keydown', e => {
              if (e.key === 'Enter') ok();
              if (e.key === 'Escape') cancel();
            });
          </script>
        </body></html>
      `;
  
      const handler = (_ev: Electron.IpcMainEvent, data: { ok: boolean; value?: string }) => {
        try { win.close(); } catch {}
        ipcMain.removeListener(channel, handler);
        resolve(data.ok ? String(data.value ?? "") : null);
      };
      ipcMain.on(channel, handler);
  
      win.loadURL("data:text/html;charset=UTF-8," + encodeURIComponent(html));
      win.on("closed", () => {
        ipcMain.removeListener(channel, handler);
        resolve(null);
      });
    });
  }
  
  // ----------------------------
  // Auth flows (Admin vs Staff)
  // ----------------------------
  async function verifyAdminOrSet(cfg: Config): Promise<boolean> {
    if (!cfg.adminHash) {
      const first = await pinPrompt({
        title: "Set Admin PIN",
        label: "Create an Admin PIN (managers only):",
        password: true,
      });
      if (!first) return false;
      cfg.adminHash = sha256(first);
      saveConfig(cfg);
      return true;
    }
    const entered = await pinPrompt({
      title: "Admin PIN Required",
      label: "Enter Admin PIN:",
      password: true,
    });
    return entered !== null && sha256(entered) === cfg.adminHash;
  }
  
  async function changeAdminPinFlow(cfg: Config): Promise<boolean> {
    const ok = await verifyAdminOrSet(cfg);
    if (!ok) return false;
  
    const np = await pinPrompt({
      title: "Change Admin PIN",
      label: "Enter new Admin PIN:",
      password: true,
    });
    if (!np) return false;
  
    const conf = await pinPrompt({
      title: "Confirm Admin PIN",
      label: "Re-enter new Admin PIN:",
      password: true,
    });
    if (!conf || conf !== np) {
      dialog.showErrorBox("Mismatch", "PINs didn’t match.");
      return false;
    }
  
    cfg.adminHash = sha256(np);
    saveConfig(cfg);
    dialog.showMessageBox({ message: "Admin PIN updated." });
    return true;
  }
  
  async function verifyPinOrSet(cfg: Config): Promise<boolean> {
    if (!cfg.pinHash) {
      const pin = await pinPrompt({
        title: "Set PIN",
        label: "Create a PIN to open the drawer:",
        password: true,
      });
      if (!pin) return false;
      cfg.pinHash = sha256(pin);
      saveConfig(cfg);
      return true;
    }
    const entered = await pinPrompt({
      title: "PIN Required",
      label: "Enter PIN to open the cash drawer:",
      password: true,
    });
    if (entered === null) return false;
    return sha256(entered) === cfg.pinHash;
  }
  
  async function setPinFlow(cfg: Config) {
    const pin = await pinPrompt({
      title: "Set/Change PIN",
      label: "Enter new PIN:",
      password: true,
    });
    if (!pin) return false;
    cfg.pinHash = sha256(pin);
    saveConfig(cfg);
    return true;
  }
  
  // ----------------------------
  // Settings window (Bond-branded)
  // ----------------------------
  function openSettings(cfg: Config) {
    if (settingsWin) { settingsWin.focus(); return; }
    settingsWin = new BrowserWindow({
      width: 560,
      height: 600,
      useContentSize: true,
      resizable: false,
      title: "Drawer Opener Settings",
      webPreferences: { nodeIntegration: true, contextIsolation: false },
    });
  
    const hotkeyMac = "⌘⇧O";
    const hotkeyWin = "Ctrl+Shift+O";
    const hotkeyTip = process.platform === "darwin" ? hotkeyMac : hotkeyWin;
  
    const logoFile = resolveAsset("bond_logo.png");
    const logoSrc = logoFile
      ? `data:image/png;base64,${fs.readFileSync(logoFile).toString("base64")}`
      : "";
  
    const html = `
    <html>
    <head>
      <meta charset="utf-8" />
      <style>
        :root {
          --bond-navy: #0e4a6b;
          --bond-gold: #f1b82d;
          --bond-slate: #f5f7fa;
          --text: #1f2937;
          --muted: #6b7280;
          --input: #e5e7eb;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0; padding: 0;
          font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          background: var(--bond-slate);
          color: var(--text);
        }
        .wrap { max-width: 520px; margin: 0 auto; padding: 20px 20px 28px; }
        .card {
          background: #fff; border-radius: 14px;
          box-shadow: 0 6px 24px rgba(14,74,107,0.08); overflow: hidden; border: 1px solid #eef2f7;
        }
        .header { display: flex; align-items: center; gap: 14px; padding: 16px 18px;
          background: linear-gradient(135deg, var(--bond-navy), #0b3d57); color: #fff; }
        .header img { width: 72px; height: 28px; border-radius: 6px; background: #fff; }
        .header h2 { margin: 0; font-weight: 700; letter-spacing: .2px; font-size: 16px; }
        .content { padding: 18px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        .grid.full { grid-template-columns: 1fr; }
        label { font-size: 12px; color: var(--muted); margin-bottom: 6px; display: block; }
        input {
          width: 100%; padding: 10px 12px; font-size: 14px;
          border: 1px solid var(--input); border-radius: 10px; outline: none;
        }
        input:focus { border-color: var(--bond-navy); box-shadow: 0 0 0 3px rgba(14,74,107,0.12); }
        .row { margin-bottom: 10px; }
        .btns { display: flex; gap: 10px; margin-top: 6px; }
        .btn { appearance: none; border: 0; cursor: pointer; padding: 10px 14px; border-radius: 10px; font-weight: 600; font-size: 14px; }
        .btn-primary { background: var(--bond-navy); color: #fff; }
        .btn-primary:hover { filter: brightness(1.04); }
        .btn-secondary { background: #eef2f7; color: #0b3d57; }
        .btn-danger { background: #fee2e2; color: #991b1b; }
        .section-title { margin: 16px 0 8px; font-weight: 700; color: var(--bond-navy); font-size: 13px; }
        .hint { font-size: 12px; color: var(--muted); }
        .footer { padding: 10px 18px 16px; display: flex; justify-content: space-between; align-items: center; }
        .tag { display:inline-block;background:rgba(241,184,45,.15); color:#8a6d00; padding:4px 8px; border-radius:8px; font-size:12px; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="card">
          <div class="header">
            ${logoSrc ? `<img src="${logoSrc}" alt="Bond" />` : ""}
            <h2>Drawer Opener — Settings</h2>
          </div>
          <div class="content">
            <div class="section-title">Printer</div>
            <div class="grid">
              <div class="row">
                <label>Printer IP</label>
                <input id="ip" placeholder="e.g. 192.168.1.45 or simulate" />
              </div>
              <div class="row">
                <label>Printer Port</label>
                <input id="port" type="number" value="9100" />
              </div>
            </div>
  
            <div class="grid">
              <div class="row">
                <label>Drawer Channel (0 or 1)</label>
                <input id="channel" type="number" min="0" max="1" value="0" />
              </div>
              <div></div>
            </div>
  
            <div class="grid">
              <div class="row">
                <label>Pulse On (t1 0–255)</label>
                <input id="on" type="number" value="50" />
              </div>
              <div class="row">
                <label>Pulse Off (t2 0–255)</label>
                <input id="off" type="number" value="200" />
              </div>
            </div>
  
            <div class="btns">
              <button id="save" class="btn btn-primary">Save</button>
              <button id="test" class="btn btn-secondary">Test Open</button>
            </div>
  
            <div class="section-title">Security</div>
            <div class="grid full">
              <div class="hint">Staff PIN opens the drawer. Admin PIN controls Settings & PIN changes.</div>
            </div>
            <div class="btns">
              <button id="setpin" class="btn btn-secondary">Set/Change Staff PIN</button>
              <button id="changeAdmin" class="btn btn-danger">Change Admin PIN</button>
            </div>
          </div>
          <div class="footer">
            <span class="tag">Bond Sports</span>
            <span class="hint" title="Use this hotkey to open the drawer directly from anywhere.">
             Hotkey: ${hotkeyTip} <span style="color:#9aa4af">(mac: ${hotkeyMac} • win: ${hotkeyWin})</span>
            </span>
          </div>
        </div>
      </div>
  
      <script>
        const { ipcRenderer } = require('electron');
        ipcRenderer.invoke('loadCfg').then(cfg => {
          document.getElementById('ip').value = cfg.printerIp || '';
          document.getElementById('port').value = cfg.printerPort || 9100;
          document.getElementById('channel').value = cfg.drawerChannel || 0;
          document.getElementById('on').value = cfg.pulseOn || 50;
          document.getElementById('off').value = cfg.pulseOff || 200;
        });
  
        const readCfg = () => ({
          printerIp: document.getElementById('ip').value.trim(),
          printerPort: parseInt(document.getElementById('port').value, 10),
          drawerChannel: parseInt(document.getElementById('channel').value, 10),
          pulseOn: parseInt(document.getElementById('on').value, 10),
          pulseOff: parseInt(document.getElementById('off').value, 10),
        });
  
        document.getElementById('save').onclick = () => {
          ipcRenderer.invoke('saveCfg', readCfg()).then(()=>alert('Saved.'));
        };
        document.getElementById('test').onclick = () => {
          ipcRenderer.invoke('testOpen', readCfg()).then(ok => {
            alert(ok ? 'Drawer opened!' : 'Failed to open drawer. Check IP/channel/pulse.');
          });
        };
        document.getElementById('setpin').onclick = () => {
          ipcRenderer.invoke('setPin').then(ok => {
            alert(ok ? 'PIN updated.' : 'PIN not changed.');
          });
        };
        document.getElementById('changeAdmin').onclick = () => {
          ipcRenderer.invoke('changeAdminPin').then(()=>{});
        };
      </script>
    </body>
    </html>`;
  
    settingsWin.loadURL("data:text/html;charset=UTF-8," + encodeURIComponent(html));
    settingsWin.on("closed", () => { settingsWin = undefined; });
  }
  
  // ----------------------------
  // Drawer flow
  // ----------------------------
  async function openDrawerFlow(cfg: Config) {
    if (!cfg.printerIp) {
      dialog.showErrorBox("Not Configured", "Please set printer IP in Settings.");
      return;
    }
  
    const ok = await verifyPinOrSet(cfg);
    if (!ok) return;
  
    const success = await sendDrawerKick(cfg);
    if (!success) {
      dialog.showErrorBox("Failed", "Could not open the cash drawer. Check IP, channel, pulse, and that the printer is reachable.");
    }
  }
  
  function sendDrawerKick(cfg: Config): Promise<boolean> {
    if (cfg.printerIp.trim().toLowerCase() === "simulate") {
      return new Promise((resolve) => setTimeout(() => resolve(true), 150));
    }
  
    return new Promise((resolve) => {
      try {
        const client = new net.Socket();
        client.setTimeout(3000);
        client.connect(cfg.printerPort, cfg.printerIp, () => {
          // ESC p m t1 t2
          const bytes = Buffer.from([0x1B, 0x70, cfg.drawerChannel, cfg.pulseOn, cfg.pulseOff]);
          client.write(bytes, (err?: Error | null) => {
            client.end();
            resolve(!err);
          });
        });
        client.on("error", () => resolve(false));
        client.on("timeout", () => { client.destroy(); resolve(false); });
      } catch {
        resolve(false);
      }
    });
  }
  
  // ----------------------------
  // IPC
  // ----------------------------
  ipcMain.handle("loadCfg", async () => loadConfig());
  
  ipcMain.handle("saveCfg", async (_evt: IpcMainInvokeEvent, partial: Partial<Config>) => {
    const merged = { ...loadConfig(), ...partial };
    saveConfig(merged);
    return true;
  });
  
  ipcMain.handle("testOpen", async (_evt: IpcMainInvokeEvent, override?: Partial<Config>) => {
    const cfg = { ...loadConfig(), ...(override || {}) } as Config;
    return sendDrawerKick(cfg);
  });
  
  ipcMain.handle("setPin", async () => {
    const cfg = loadConfig();
    // Admin only can change staff PIN:
    if (!(await verifyAdminOrSet(cfg))) return false;
    return setPinFlow(cfg);
  });
  
  ipcMain.handle("changeAdminPin", async () => {
    const cfg = loadConfig();
    return changeAdminPinFlow(cfg);
  });
  
  // ----------------------------
  // App lifecycle
  // ----------------------------
  app.whenReady().then(async () => {
    const cfg = loadConfig();
    buildTray(cfg);
  
    // First run: ensure Admin PIN exists
    if (!cfg.adminHash) {
      await verifyAdminOrSet(cfg);
    }
  
    // If no printer yet, let admin configure it
    if (!loadConfig().printerIp) {
      if (await verifyAdminOrSet(loadConfig())) openSettings(loadConfig());
    }
  
    const combo = process.platform === "darwin" ? "Command+Shift+O" : "Control+Shift+O";
    globalShortcut.register(combo, () => openDrawerFlow(loadConfig()));
  });
  
  // Keep app running even if all windows are closed (tray stays alive)
  app.on("window-all-closed", () => { /* no-op */ });
  app.on("will-quit", () => { globalShortcut.unregisterAll(); });
  
  // ----------------------------
  // Tray
  // ----------------------------
  function buildTray(_cfg: Config) {
    const { nativeImage } = require("electron");
  
    // Create an “empty” icon and use an emoji as the title so it shows in the macOS menu bar
    tray = new Tray(nativeImage.createEmpty());
    tray.setTitle("💵"); // You could also try "🛒" or "🖨️" if you prefer
    tray.setToolTip("Drawer Opener");
  
    const menu = Menu.buildFromTemplate([
      { label: "Open Cash Drawer", click: () => openDrawerFlow(loadConfig()) },
      { type: "separator" },
      { label: "Settings", click: async () => {
          const cfg = loadConfig();
          if (await verifyAdminOrSet(cfg)) openSettings(cfg);
        }},
      { label: "Change Admin PIN", click: async () => {
          const cfg = loadConfig();
          await changeAdminPinFlow(cfg);
        }},
      { type: "separator" },
      { label: "Quit", role: "quit" },
    ]);
    tray.setContextMenu(menu);
  }