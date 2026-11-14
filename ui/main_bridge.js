// ui/main_bridge.js
(() => {
  'use strict';

  const VERSION = '1';
  const DEFAULT_CONTRACT_ID = 'sidebar-list-v1';
  const DEFAULT_MAIN_URL = 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html';
  const DEFAULT_EXCLUDE_URLS = ['plugin-sandbox.html', 'resource-manager.html', 'cua-permission-panel.html'];
  const ACTION_TIMEOUT_MS = 15000;
  const MAX_ACTIONS_PER_WINDOW = 16;
  const MAX_MAILBOX_FILE_BYTES = 65536;
  const MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024;

  function resolveBuiltins(overrides) {
    const ov = overrides && typeof overrides === 'object' ? overrides : {};
    const getBuiltin =
      typeof process !== 'undefined' && typeof process.getBuiltinModule === 'function'
        ? process.getBuiltinModule.bind(process)
        : null;
    if (!getBuiltin && (!ov.fs || !ov.path || !ov.crypto || !ov.moduleApi)) {
      return { ok: false, code: 'GET_BUILTIN_MODULE_UNAVAILABLE' };
    }
    const moduleApi = ov.moduleApi || (getBuiltin ? getBuiltin('module') : null);
    const fs = ov.fs || (getBuiltin ? getBuiltin('fs') : null);
    const path = ov.path || (getBuiltin ? getBuiltin('path') : null);
    const crypto = ov.crypto || (getBuiltin ? getBuiltin('crypto') : null);
    if (!fs || !path || !crypto || !moduleApi) {
      return { ok: false, code: 'BUILTIN_MODULES_MISSING' };
    }
    return { ok: true, moduleApi, fs, path, crypto };
  }

  function resolveElectron(config, moduleApi, path) {
    if (config && config.electron) {
      return { ok: true, electron: config.electron };
    }
    const resourcesPath = (config && config.resourcesPath) || (typeof process !== 'undefined' ? process.resourcesPath : '');
    const pkgPath = (config && config.appPackageJsonPath) || (resourcesPath ? path.join(resourcesPath, 'app.asar', 'package.json') : '');
    if (!pkgPath || typeof moduleApi.createRequire !== 'function') {
      return { ok: false, code: 'ELECTRON_CREATE_REQUIRE_UNAVAILABLE' };
    }
    try {
      const requireFromApp = moduleApi.createRequire(pkgPath);
      const electron = requireFromApp('electron');
      return { ok: true, electron };
    } catch (err) {
      return { ok: false, code: 'ELECTRON_LOAD_FAILED', detail: String((err && err.message) || err) };
    }
  }

  function isSafeId(id) {
    return typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id);
  }

  function safeAppGenName(appGen) {
    return String(appGen || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_');
  }

  async function installMainBridge(rawConfig) {
    const config = rawConfig && typeof rawConfig === 'object' ? rawConfig : {};
    const builtins = resolveBuiltins(config.builtins);
    if (!builtins.ok) {
      return { ok: false, code: builtins.code, diagnostics: { processType: typeof process !== 'undefined' ? process.type : null } };
    }
    const { moduleApi, fs, path, crypto } = builtins;

    const procType = config.processType !== undefined ? config.processType : (typeof process !== 'undefined' ? process.type : null);
    if (procType !== 'browser') {
      return { ok: false, code: 'NOT_BROWSER_PROCESS', diagnostics: { processType: procType } };
    }

    const elRes = resolveElectron(config, moduleApi, path);
    if (!elRes.ok) {
      return { ok: false, code: elRes.code, diagnostics: { detail: elRes.detail || null } };
    }
    const electron = elRes.electron;
    if (
      !electron ||
      !electron.app ||
      typeof electron.app.on !== 'function' ||
      typeof electron.app.removeListener !== 'function' ||
      !electron.webContents ||
      typeof electron.webContents.getAllWebContents !== 'function'
    ) {
      return { ok: false, code: 'CAPABILITY_CHECK_FAILED', diagnostics: { reason: 'ELECTRON_API_INCOMPLETE' } };
    }

    const appGen = String(config.appGen || '');
    const stateRoot = String(config.stateRoot || '');
    const bundleSource = String(config.bundleSource || '');
    if (!appGen || !stateRoot || !bundleSource) {
      return { ok: false, code: 'INVALID_BRIDGE_CONFIG' };
    }

    const bundleSha =
      String(config.bundleSha || '') ||
      crypto.createHash('sha256').update(bundleSource, 'utf8').digest('hex');
    const sourceSha =
      String(config.sourceSha || '') ||
      crypto.createHash('sha256').update(`${bundleSha}:${config.bridgeSourceSha || VERSION}`, 'utf8').digest('hex');
    const contractId = String(config.contractId || DEFAULT_CONTRACT_ID);
    const adapterId = String(config.adapterId || 'zcode-3.17.2');
    const mainUrlPrefix = String(config.mainUrlPrefix || DEFAULT_MAIN_URL);
    const excludeUrls = Array.isArray(config.excludeUrlSubstrings) ? config.excludeUrlSubstrings : DEFAULT_EXCLUDE_URLS;
    const pollIntervalMs = Math.max(250, Number(config.pollIntervalMs || 1500));

    const prev = globalThis.__SS_MAIN_BRIDGE__;
    if (prev && prev.active && prev.appGen === appGen && prev.sourceSha === sourceSha && prev.bundleSha === bundleSha) {
      if (typeof prev.tickOnce === 'function') {
        try {
          await prev.tickOnce();
        } catch (_) {}
      }
      return {
        ok: true,
        reused: true,
        appGen: prev.appGen,
        sourceSha: prev.sourceSha,
        bundleSha: prev.bundleSha,
        bootNonce: prev.bootNonce,
        diagnostics: typeof prev.getDiagnostics === 'function' ? prev.getDiagnostics() : {},
      };
    }

    if (prev && typeof prev.dispose === 'function') {
      try {
        await prev.dispose({ reason: 'hot_swap' });
      } catch (_) {}
    }

    const bootNonce =
      typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : crypto.randomBytes(16).toString('hex');
    const safeGen = safeAppGenName(appGen);
    const runtimeDir = path.join(stateRoot, 'sidebar-ui', 'runtime', safeGen);
    const actionsDir = path.join(runtimeDir, 'actions');
    const receiptsDir = path.join(runtimeDir, 'receipts');
    const handshakePath = path.join(runtimeDir, 'handshake.json');
    const transportOwnerPath = path.join(runtimeDir, 'transport_owner.json');
    const snapshotPath = path.join(stateRoot, 'exports', 'sidebar-tree-v1.json');

    const myUid = typeof process !== 'undefined' && typeof process.getuid === 'function' ? process.getuid() : null;

    function ensureSafeDir(dirPath) {
      fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
      const st = fs.lstatSync(dirPath);
      if (st.isSymbolicLink() || !st.isDirectory()) {
        throw new Error(`UNSAFE_DIR:${dirPath}`);
      }
      if (myUid !== null && st.uid !== myUid) {
        throw new Error(`UNTRUSTED_DIR_UID:${dirPath}`);
      }
    }

    function readRegularOwnedJson(filePath, maxBytes = MAX_MAILBOX_FILE_BYTES) {
      let st;
      let raw;
      if (typeof fs.openSync === 'function' && typeof fs.fstatSync === 'function' && typeof fs.closeSync === 'function') {
        const nofollow = (fs.constants && fs.constants.O_NOFOLLOW) || 0;
        const rdonly = (fs.constants && fs.constants.O_RDONLY) || 0;
        let fd;
        try {
          fd = fs.openSync(filePath, rdonly | nofollow);
          st = fs.fstatSync(fd);
          if (!st.isFile() || st.size > maxBytes || (myUid !== null && st.uid !== myUid)) {
            return null;
          }
          raw = fs.readFileSync(fd, 'utf8');
        } catch (_) {
          return null;
        } finally {
          if (fd !== undefined) {
            try {
              fs.closeSync(fd);
            } catch (_) {}
          }
        }
      } else {
        try {
          st = fs.lstatSync(filePath);
        } catch (_) {
          return null;
        }
        if (st.isSymbolicLink() || !st.isFile() || st.size > maxBytes) {
          return null;
        }
        if (myUid !== null && st.uid !== myUid) {
          return null;
        }
        try {
          raw = fs.readFileSync(filePath, 'utf8');
        } catch (_) {
          return null;
        }
      }
      try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : null;
      } catch (_) {
        return null;
      }
    }

    function atomicWriteJson(filePath, obj) {
      const dir = path.dirname(filePath);
      ensureSafeDir(dir);
      const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid || 0}.${crypto.randomBytes(6).toString('hex')}.tmp`);
      const payload = JSON.stringify(obj, null, 2);
      fs.writeFileSync(tmp, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      fs.renameSync(tmp, filePath);
    }

    function unlinkIfOwnedRegular(filePath) {
      try {
        const st = fs.lstatSync(filePath);
        if (st.isSymbolicLink() || !st.isFile()) return;
        if (myUid !== null && st.uid !== myUid) return;
        fs.unlinkSync(filePath);
      } catch (_) {}
    }

    ensureSafeDir(runtimeDir);
    ensureSafeDir(actionsDir);
    ensureSafeDir(receiptsDir);

    const state = {
      version: VERSION,
      appGen,
      safeAppGen: safeGen,
      sourceSha,
      bundleSha,
      bootNonce,
      contractId,
      adapterId,
      active: true,
      disposed: false,
      lastSnapshotMeta: { storeInstanceId: '', projectionRevision: 0 },
      lastError: null,
    };

    const windowsMap = new Map(); // wcId -> window record
    const wcListeners = new Map(); // wcId -> { wc, onFinishLoad, onDestroyed }
    const reconcileChains = new Map(); // wcId -> Promise
    const actionQueuedAtCache = new Map(); // actionId -> queuedAtMs
    let timer = null;
    let tickInFlight = false;

    function isQualifiedWebContents(wc) {
      if (!wc) return false;
      if (typeof wc.isDestroyed === 'function' && wc.isDestroyed()) return false;
      if (typeof wc.executeJavaScript !== 'function') return false;
      if (typeof wc.getType === 'function') {
        const t = wc.getType();
        if (t !== 'window') return false;
      }
      const url = typeof wc.getURL === 'function' ? String(wc.getURL() || '') : '';
      if (!url || url.startsWith('devtools://') || url.startsWith('chrome-devtools://') || url === 'about:blank') {
        return false;
      }
      if (!url.startsWith(mainUrlPrefix)) return false;
      for (const ex of excludeUrls) {
        if (ex && url.includes(ex)) return false;
      }
      return true;
    }

    function readWindowTransportOwner(wcId) {
      const toFile = readRegularOwnedJson(transportOwnerPath);
      if (toFile && toFile.appGen === appGen) {
        const perWin = toFile.windows && typeof toFile.windows === 'object' ? toFile.windows[String(wcId)] : null;
        if (perWin === 'cdp' || perWin === 'bridge') return perWin;
        if (toFile.owner === 'cdp' || toFile.owner === 'bridge') return toFile.owner;
      }
      if (config.transportOwner === 'cdp') return 'cdp';
      return 'bridge';
    }

    function serializeForWindow(wcId, fn) {
      const prevChain = reconcileChains.get(wcId) || Promise.resolve();
      const next = prevChain.then(fn, fn);
      reconcileChains.set(wcId, next.catch(() => {}));
      return next;
    }

    function ensureWindowRecord(wc) {
      const wcId = wc.id;
      let rec = windowsMap.get(wcId);
      if (!rec) {
        rec = {
          wc,
          webContentsId: wcId,
          epoch: 1,
          pushedStoreId: null,
          pushedRev: null,
          capabilities: null,
          selfTestState: null,
          diagnostics: null,
          status: null,
          transportOwner: 'bridge',
          lastError: null,
        };
        windowsMap.set(wcId, rec);
      } else {
        rec.wc = wc;
      }
      return rec;
    }

    function detachWindowListeners(wcId) {
      const entry = wcListeners.get(wcId);
      if (!entry) return;
      try {
        if (entry.wc && typeof entry.wc.removeListener === 'function') {
          entry.wc.removeListener('did-finish-load', entry.onFinishLoad);
          entry.wc.removeListener('destroyed', entry.onDestroyed);
        }
      } catch (_) {}
      wcListeners.delete(wcId);
    }

    function attachWindowListeners(wc) {
      if (!wc || (typeof wc.isDestroyed === 'function' && wc.isDestroyed())) return;
      if (typeof wc.getType === 'function' && wc.getType() === 'devtools') return;
      const wcId = wc.id;
      if (wcListeners.has(wcId)) return;
      if (typeof wc.on !== 'function') return;

      const onFinishLoad = () => {
        if (!state.active) return;
        const rec = ensureWindowRecord(wc);
        rec.epoch += 1;
        rec.pushedStoreId = null;
        rec.pushedRev = null;
        rec.status = null;
        if (isQualifiedWebContents(wc)) {
          serializeForWindow(wcId, () => reconcileWindow(wc, { snap: readSnapshot() })).then(() => {
            writeHandshake();
          });
        } else {
          writeHandshake();
        }
      };

      const onDestroyed = () => {
        detachWindowListeners(wcId);
        windowsMap.delete(wcId);
        reconcileChains.delete(wcId);
        writeHandshake();
      };

      wc.on('did-finish-load', onFinishLoad);
      wc.on('destroyed', onDestroyed);
      wcListeners.set(wcId, { wc, onFinishLoad, onDestroyed });
    }

    function readSnapshot() {
      const snap = readRegularOwnedJson(snapshotPath, MAX_SNAPSHOT_BYTES);
      if (!snap || snap.schemaVersion !== 1 || !Array.isArray(snap.nodes)) return null;
      return snap;
    }

    function cleanupStaleBootFiles() {
      for (const dir of [receiptsDir, actionsDir]) {
        let names = [];
        try {
          names = fs.readdirSync(dir);
        } catch (_) {
          continue;
        }
        for (const name of names) {
          if (!name.endsWith('.json') || name.startsWith('.')) continue;
          const aid = name.slice(0, -5);
          if (!isSafeId(aid)) continue;
          const fp = path.join(dir, name);
          const item = readRegularOwnedJson(fp);
          if (!item) continue;
          if (item.appGen === appGen && item.bootNonce && item.bootNonce !== bootNonce) {
            unlinkIfOwnedRegular(fp);
          }
        }
      }
    }

    function collectMatchingReceipts(wcId, epoch, seenActionIds) {
      const receipts = [];
      let names = [];
      try {
        names = fs.readdirSync(receiptsDir);
      } catch (_) {
        return receipts;
      }
      for (const name of names) {
        if (!name.endsWith('.json') || name.startsWith('.')) continue;
        const aid = name.slice(0, -5);
        if (!isSafeId(aid) || (seenActionIds && seenActionIds.has(aid))) continue;
        const rp = path.join(receiptsDir, name);
        const r = readRegularOwnedJson(rp);
        if (!r || r.actionId !== aid) continue;
        if (r.appGen !== appGen) continue;
        if (r.bootNonce !== bootNonce) {
          unlinkIfOwnedRegular(rp);
          unlinkIfOwnedRegular(path.join(actionsDir, `${aid}.json`));
          continue;
        }
        if (Number(r.webContentsId) !== Number(wcId)) continue;
        if (Number(r.rendererEpoch) < Number(epoch)) {
          unlinkIfOwnedRegular(rp);
          unlinkIfOwnedRegular(path.join(actionsDir, `${aid}.json`));
          continue;
        }
        if (Number(r.rendererEpoch) !== Number(epoch)) continue;
        receipts.push(r);
      }
      return receipts;
    }

    async function reconcileWindow(wc, ctx = {}) {
      if (!state.active || !isQualifiedWebContents(wc)) return null;
      const wcId = wc.id;
      const rec = ensureWindowRecord(wc);
      const epoch = rec.epoch;

      try {
        const probe = await wc.executeJavaScript(
          `(() => {
            const t = window.__SS_SIDEBAR_TREE__;
            return {
              alive: Boolean(t && t.alive),
              payloadSha: window.__SS_PAYLOAD_SHA__ || null,
              transportOwner: window.__SS_TRANSPORT_OWNER__ || null,
              bootNonce: window.__SS_BOOT_NONCE__ || null
            };
          })()`
        );

        const fileOwner = readWindowTransportOwner(wcId);
        const isCdpOwned = (probe && probe.transportOwner === 'cdp') || fileOwner === 'cdp';
        if (isCdpOwned) {
          rec.transportOwner = 'cdp';
          const stCdp = await wc.executeJavaScript('window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.getStatus() : null');
          rec.status = stCdp && typeof stCdp === 'object' ? stCdp : null;
          rec.lastError = null;
          return rec.status;
        }

        rec.transportOwner = 'bridge';
        const needsInject = !probe || !probe.alive || probe.payloadSha !== bundleSha;
        if (needsInject) {
          if (probe && probe.alive) {
            try {
              const preDrain = await wc.executeJavaScript(
                "(() => { if (window.__SS_TRANSPORT_OWNER__ === 'cdp') return []; return window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.drainActions === 'function' ? window.__SS_SIDEBAR_TREE__.drainActions() : []; })()"
              );
              if (Array.isArray(preDrain) && preDrain.length > 0) {
                const preSnap = ctx.snap !== undefined ? ctx.snap : readSnapshot();
                const preStoreId = (preSnap && preSnap.storeInstanceId) || rec.pushedStoreId || '';
                const preRev = preSnap ? Number(preSnap.projectionRevision || 0) : Number(rec.pushedRev || 0);
                for (const act of preDrain.slice(0, MAX_ACTIONS_PER_WINDOW)) {
                  if (!act || typeof act !== 'object') continue;
                  const aid = String(act.actionId || act.action_id || '');
                  if (!isSafeId(aid)) continue;
                  const actionPath = path.join(actionsDir, `${aid}.json`);
                  let actionExists = false;
                  try {
                    fs.lstatSync(actionPath);
                    actionExists = true;
                  } catch (_) {
                    actionExists = false;
                  }
                  if (!actionExists) {
                    let queuedAt = actionQueuedAtCache.get(aid);
                    if (!queuedAt) {
                      queuedAt = Number(act.queuedAt) > 0 ? Number(act.queuedAt) : Date.now();
                      actionQueuedAtCache.set(aid, queuedAt);
                    }
                    atomicWriteJson(actionPath, {
                      schemaVersion: 1,
                      actionId: aid,
                      appGen,
                      bootNonce,
                      webContentsId: wcId,
                      rendererEpoch: epoch,
                      storeInstanceId: preStoreId,
                      projectionRevision: preRev,
                      queuedAt,
                      deadlineAt: queuedAt + ACTION_TIMEOUT_MS,
                      action: act,
                    });
                  }
                }
              }
            } catch (_) {}
          }
          await wc.executeJavaScript(
            'try { window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy(); delete window.__SS_ZCODE_ADAPTER__; } catch (_) {}'
          );
          await wc.executeJavaScript(bundleSource);
          await wc.executeJavaScript(
            `window.__SS_PAYLOAD_SHA__ = ${JSON.stringify(bundleSha)}; window.__SS_TRANSPORT_OWNER__ = 'bridge'; window.__SS_BOOT_NONCE__ = ${JSON.stringify(bootNonce)};`
          );
          rec.pushedStoreId = null;
          rec.pushedRev = null;
        } else if (!probe || probe.transportOwner !== 'bridge' || probe.bootNonce !== bootNonce) {
          await wc.executeJavaScript(
            `window.__SS_TRANSPORT_OWNER__ = 'bridge'; window.__SS_BOOT_NONCE__ = ${JSON.stringify(bootNonce)};`
          );
        }

        const capProbe = await wc.executeJavaScript(
          `(() => {
            const a = window.__SS_ZCODE_ADAPTER__;
            if (!a) {
              return {
                contractId: ${JSON.stringify(contractId)},
                state: 'unsupported',
                capabilities: { mount: false, navigation: false, chatViewport: false, hostIndexSync: false, dedup: false },
                diagnostics: { reason: 'ADAPTER_MISSING' }
              };
            }
            if (typeof a.selfTest === 'function') {
              return a.selfTest();
            }
            const sc = typeof a.selfCheck === 'function' ? a.selfCheck() : {};
            const mount = Boolean(sc && sc.sidebarFound);
            const nav = Boolean(sc && sc.navigatorResolved);
            return {
              contractId: ${JSON.stringify(contractId)},
              state: mount && nav ? 'ready' : 'waiting',
              capabilities: {
                mount,
                navigation: nav,
                chatViewport: true,
                hostIndexSync: typeof a.syncUnindexedNodes === 'function',
                dedup: typeof a.suppressDuplicates === 'function'
              },
              diagnostics: sc || {}
            };
          })()`
        );

        rec.capabilities = (capProbe && capProbe.capabilities) || {};
        rec.selfTestState = (capProbe && capProbe.state) || 'waiting';
        rec.diagnostics = (capProbe && capProbe.diagnostics) || {};

        const snap = ctx.snap !== undefined ? ctx.snap : readSnapshot();
        const snapStoreId = snap ? String(snap.storeInstanceId || '') : '';
        const snapRev = snap ? Number(snap.projectionRevision || 0) : 0;
        if (snap) {
          state.lastSnapshotMeta = { storeInstanceId: snapStoreId, projectionRevision: snapRev };
          if (rec.pushedStoreId !== snapStoreId || rec.pushedRev !== snapRev) {
            const canSyncIndex = Boolean(rec.capabilities && rec.capabilities.hostIndexSync !== false);
            const pushRes = await wc.executeJavaScript(
              `(async () => {
                const s = JSON.parse(${JSON.stringify(JSON.stringify(snap))});
                if (${canSyncIndex ? 'true' : 'false'} && window.__SS_ZCODE_ADAPTER__ && window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes) {
                  try { await window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes(s); } catch (_) {}
                }
                return window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.update(s) : { ok: false, code: 'NO_CONTROLLER' };
              })()`
            );
            if (pushRes && pushRes.ok) {
              rec.pushedStoreId = snapStoreId;
              rec.pushedRev = snapRev;
            }
          }
        }

        const effectiveStoreId = (snap && snap.storeInstanceId) || rec.pushedStoreId || '';
        const effectiveRev = snap ? Number(snap.projectionRevision || 0) : Number(rec.pushedRev || 0);

        const drained = await wc.executeJavaScript(
          "(() => { if (window.__SS_TRANSPORT_OWNER__ === 'cdp') return []; return window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.drainActions === 'function' ? window.__SS_SIDEBAR_TREE__.drainActions() : []; })()"
        );
        const actions = Array.isArray(drained) ? drained.slice(0, MAX_ACTIONS_PER_WINDOW) : [];
        const ackList = [];
        const ackSeenIds = new Set();

        for (const act of actions) {
          if (!act || typeof act !== 'object') continue;
          const aid = String(act.actionId || act.action_id || '');
          if (!isSafeId(aid)) continue;

          const receiptPath = path.join(receiptsDir, `${aid}.json`);
          const existingReceipt = readRegularOwnedJson(receiptPath);
          if (
            existingReceipt &&
            existingReceipt.actionId === aid &&
            existingReceipt.appGen === appGen &&
            existingReceipt.bootNonce === bootNonce &&
            Number(existingReceipt.webContentsId) === Number(wcId) &&
            Number(existingReceipt.rendererEpoch) === Number(epoch)
          ) {
            if (!ackSeenIds.has(aid)) {
              ackSeenIds.add(aid);
              ackList.push(existingReceipt);
            }
            continue;
          }

          const actionPath = path.join(actionsDir, `${aid}.json`);
          let actionExists = false;
          try {
            fs.lstatSync(actionPath);
            actionExists = true;
          } catch (_) {
            actionExists = false;
          }
          if (!actionExists) {
            let queuedAt = actionQueuedAtCache.get(aid);
            if (!queuedAt) {
              queuedAt = Number(act.queuedAt) > 0 ? Number(act.queuedAt) : Date.now();
              actionQueuedAtCache.set(aid, queuedAt);
            }
            const envelope = {
              schemaVersion: 1,
              actionId: aid,
              appGen,
              bootNonce,
              webContentsId: wcId,
              rendererEpoch: epoch,
              storeInstanceId: effectiveStoreId,
              projectionRevision: effectiveRev,
              queuedAt,
              deadlineAt: queuedAt + ACTION_TIMEOUT_MS,
              action: act,
            };
            atomicWriteJson(actionPath, envelope);
          }
        }

        for (const extraReceipt of collectMatchingReceipts(wcId, epoch, ackSeenIds)) {
          ackSeenIds.add(extraReceipt.actionId);
          ackList.push(extraReceipt);
        }

        if (ackList.length > 0 && state.active) {
          const ackRes = await wc.executeJavaScript(
            `window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.ackActions === 'function' ? window.__SS_SIDEBAR_TREE__.ackActions(JSON.parse(${JSON.stringify(
              JSON.stringify(ackList)
            )})) : null`
          );
          if (ackRes && typeof ackRes.acked === 'number') {
            for (const r of ackList) {
              const aid = String(r.actionId || '');
              if (!isSafeId(aid)) continue;
              unlinkIfOwnedRegular(path.join(receiptsDir, `${aid}.json`));
              unlinkIfOwnedRegular(path.join(actionsDir, `${aid}.json`));
              actionQueuedAtCache.delete(aid);
            }
          }
        }

        const st = await wc.executeJavaScript('window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.getStatus() : null');
        rec.status = st && typeof st === 'object' ? st : null;
        rec.lastError = null;
        return rec.status;
      } catch (err) {
        rec.lastError = String((err && err.message) || err);
        return null;
      }
    }

    function writeHandshake() {
      if (!state.active) return;
      const windowsSummary = {};
      for (const [wcId, rec] of windowsMap.entries()) {
        if (!rec.wc || (typeof rec.wc.isDestroyed === 'function' && rec.wc.isDestroyed())) continue;
        if (!isQualifiedWebContents(rec.wc)) continue;
        windowsSummary[String(wcId)] = {
          webContentsId: wcId,
          rendererEpoch: rec.epoch,
          transportOwner: rec.transportOwner,
          url: typeof rec.wc.getURL === 'function' ? String(rec.wc.getURL() || '') : '',
          alive: Boolean(rec.status && rec.status.alive),
          selfTestState: rec.selfTestState,
          capabilities: rec.capabilities,
          diagnostics: rec.diagnostics,
          status: rec.status,
          lastError: rec.lastError,
        };
      }
      atomicWriteJson(handshakePath, {
        schemaVersion: 1,
        active: true,
        appGen,
        safeAppGen: safeGen,
        bootNonce,
        sourceSha,
        bundleSha,
        contractId,
        adapterId,
        storeInstanceId: state.lastSnapshotMeta.storeInstanceId,
        projectionRevision: state.lastSnapshotMeta.projectionRevision,
        transport: 'bridge',
        windows: windowsSummary,
        updatedAt: Date.now() / 1000,
      });
    }

    async function tickOnce() {
      if (!state.active || tickInFlight) return null;
      tickInFlight = true;
      try {
        cleanupStaleBootFiles();
        const snap = readSnapshot();
        const allWcs = electron.webContents.getAllWebContents() || [];
        const qualifiedIds = new Set();
        const tasks = [];
        for (const wc of allWcs) {
          if (!wc || (typeof wc.isDestroyed === 'function' && wc.isDestroyed())) continue;
          attachWindowListeners(wc);
          if (isQualifiedWebContents(wc)) {
            qualifiedIds.add(wc.id);
            tasks.push(serializeForWindow(wc.id, () => reconcileWindow(wc, { snap })));
          }
        }
        for (const wcId of [...windowsMap.keys()]) {
          if (!qualifiedIds.has(wcId)) {
            const rec = windowsMap.get(wcId);
            if (!rec || !rec.wc || (typeof rec.wc.isDestroyed === 'function' && rec.wc.isDestroyed()) || !isQualifiedWebContents(rec.wc)) {
              windowsMap.delete(wcId);
              reconcileChains.delete(wcId);
            }
          }
        }
        await Promise.all(tasks);
        writeHandshake();
        return getDiagnostics();
      } catch (err) {
        state.lastError = String((err && err.message) || err);
        return getDiagnostics();
      } finally {
        tickInFlight = false;
      }
    }

    const onWebContentsCreated = (_event, wc) => {
      if (!state.active) return;
      attachWindowListeners(wc);
      if (isQualifiedWebContents(wc)) {
        serializeForWindow(wc.id, () => reconcileWindow(wc, { snap: readSnapshot() })).then(() => {
          writeHandshake();
        });
      }
    };

    electron.app.on('web-contents-created', onWebContentsCreated);
    for (const wc of electron.webContents.getAllWebContents() || []) {
      attachWindowListeners(wc);
    }

    timer = setInterval(() => {
      tickOnce();
    }, pollIntervalMs);
    if (timer && typeof timer.unref === 'function') {
      timer.unref();
    }

    function getDiagnostics() {
      const windows = {};
      for (const [wcId, rec] of windowsMap.entries()) {
        windows[String(wcId)] = {
          webContentsId: wcId,
          rendererEpoch: rec.epoch,
          transportOwner: rec.transportOwner,
          alive: Boolean(rec.status && rec.status.alive),
          selfTestState: rec.selfTestState,
          capabilities: rec.capabilities,
          status: rec.status,
          lastError: rec.lastError,
        };
      }
      return {
        version: state.version,
        appGen: state.appGen,
        sourceSha: state.sourceSha,
        bundleSha: state.bundleSha,
        bootNonce: state.bootNonce,
        contractId: state.contractId,
        active: state.active,
        disposed: state.disposed,
        windowCount: windowsMap.size,
        listenerCount: wcListeners.size,
        windows,
        lastError: state.lastError,
      };
    }

    async function dispose() {
      if (state.disposed) return { ok: true, alreadyDisposed: true };
      state.active = false;
      state.disposed = true;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      try {
        electron.app.removeListener('web-contents-created', onWebContentsCreated);
      } catch (_) {}
      for (const wcId of [...wcListeners.keys()]) {
        detachWindowListeners(wcId);
      }
      const destroyTasks = [];
      for (const rec of windowsMap.values()) {
        if (rec.wc && !(typeof rec.wc.isDestroyed === 'function' && rec.wc.isDestroyed()) && typeof rec.wc.executeJavaScript === 'function') {
          destroyTasks.push(
            rec.wc
              .executeJavaScript(
                'try { window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy(); if (window.__SS_ZCODE_ADAPTER__ && window.__SS_ZCODE_ADAPTER__.restoreDedup) window.__SS_ZCODE_ADAPTER__.restoreDedup(); delete window.__SS_ZCODE_ADAPTER__; delete window.__SS_PAYLOAD_SHA__; delete window.__SS_TRANSPORT_OWNER__; delete window.__SS_BOOT_NONCE__; } catch (_) {}'
              )
              .catch(() => {})
          );
        }
      }
      await Promise.all(destroyTasks);
      windowsMap.clear();
      reconcileChains.clear();
      actionQueuedAtCache.clear();
      const curHs = readRegularOwnedJson(handshakePath);
      if (curHs && curHs.bootNonce === bootNonce) {
        unlinkIfOwnedRegular(handshakePath);
      }
      if (globalThis.__SS_MAIN_BRIDGE__ === bridgeApi) {
        delete globalThis.__SS_MAIN_BRIDGE__;
      }
      return { ok: true, disposed: true };
    }

    const bridgeApi = {
      version: VERSION,
      appGen,
      sourceSha,
      bundleSha,
      bootNonce,
      contractId,
      get active() {
        return state.active;
      },
      tickOnce,
      reconcileWindow,
      getDiagnostics,
      dispose,
    };

    globalThis.__SS_MAIN_BRIDGE__ = bridgeApi;
    await tickOnce();

    return {
      ok: true,
      reused: false,
      appGen,
      sourceSha,
      bundleSha,
      bootNonce,
      contractId,
      diagnostics: getDiagnostics(),
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      installMainBridge,
      resolveBuiltins,
      resolveElectron,
      safeAppGenName,
    };
  }
  globalThis.__SS_INSTALL_MAIN_BRIDGE__ = installMainBridge;
  if (globalThis.__SS_BRIDGE_CONFIG__) {
    return installMainBridge(globalThis.__SS_BRIDGE_CONFIG__);
  }
})();
