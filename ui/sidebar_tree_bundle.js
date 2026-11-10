// ui/sidebar_tree_bundle.js
(() => {
  'use strict';
  const G = typeof window !== 'undefined' ? window : globalThis;
  const VERSION = '3';
  const prev = G.__SS_SIDEBAR_TREE__;
  if (prev && prev.version === VERSION && prev.alive) return;
  if (prev && prev.destroy) {
    try {
      prev.destroy();
    } catch (_) {}
  }
  const staleStyle = typeof document !== 'undefined' ? document.getElementById('ss-sidebar-tree-style') : null;
  if (staleStyle) staleStyle.remove();

  const A = G.__SS_ZCODE_ADAPTER__;
  const STYLE_ID = 'ss-sidebar-tree-style';
  const OWN = 'data-ss-owned';
  const CSS = `
[data-ss-suppressed]{display:none!important}
li[data-ss-has-children="true"] div.flex-1.h-6 > .min-w-0.flex-1.overflow-hidden,
li[data-ss-has-children="true"] div.flex.min-w-0.items-center > p.min-w-0.flex-1{flex:0 1 auto!important}
.ss-tree-chevron{order:99;flex:0 0 18px;width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;
  border:0;background:none;padding:0;color:var(--color-foreground-subtlest,#87888f);cursor:pointer;border-radius:4px;
  transition:transform .12s ease;pointer-events:auto!important}
.ss-tree-chevron:hover{background:var(--color-surface-hover)}
.ss-tree-chevron[aria-expanded="false"]{transform:rotate(-90deg)}
[data-ss-tree-host][hidden]{display:none!important}
[data-ss-tree-host]{--ss-line:var(--color-border,#8888)}
.ss-child-list{list-style:none;margin:0 4px 0 var(--ss-indent,26px);padding:0}
.ss-child-list .ss-child-list{margin-left:14px}
.ss-child-item{position:relative;padding-left:13px;margin:0;list-style:none}
.ss-child-item:not(:last-child)::before{content:"";position:absolute;left:0;top:0;bottom:0;border-left:1.5px solid var(--ss-line);pointer-events:none}
.ss-child-item:last-child::after{content:"";position:absolute;left:0;top:0;width:9px;height:14px;border-left:1.5px solid var(--ss-line);
  border-bottom:1.5px solid var(--ss-line);border-bottom-left-radius:6px;pointer-events:none}
.ss-child-row{display:flex;align-items:center;gap:2px}
.ss-child-link{flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:5px;min-height:25px;padding:2px 8px;border:0;
  background:none;border-radius:8px;color:var(--color-foreground);font:inherit;font-size:13px;text-align:left;cursor:pointer}
.ss-child-link:hover{background:var(--color-surface-hover)}
.ss-child-link[aria-current="page"],.ss-child-link[aria-current="true"]{background:var(--color-selected)}
.ss-child-link[data-nav="pending"]{opacity:.6;cursor:progress}
.ss-child-title{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ss-child-handle{flex:0 1 auto;max-width:78px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11.5px;color:var(--color-foreground-subtlest,#87888f)}
.ss-child-link[data-status="done"] .ss-child-title{color:var(--color-foreground-subtlest,#87888f)}
.ss-status{flex:none;width:7px;height:7px;border-radius:9999px}
.ss-status[data-s="waiting"]{background:var(--color-warning)}
.ss-status[data-s="error"]{background:var(--color-destructive)}
.ss-status[data-s="running"]{width:9px;height:9px;border:1.5px solid var(--color-foreground-subtlest,#87888f);
  border-top-color:transparent;background:none;animation:ss-spin .9s linear infinite}
.ss-status[data-s="none"],.ss-status[data-s="done"]{display:none}
@keyframes ss-spin{to{transform:rotate(360deg)}}
.ss-comm-badge{flex:none;display:inline-flex;align-items:center;gap:3px;font-size:11px;color:var(--color-foreground-subtlest,#87888f)}
.ss-comm-badge .ss-dot{width:6px;height:6px;border-radius:9999px;background:var(--color-foreground)}
.ss-comm-badge .ss-dot.hollow{background:none;border:1px solid var(--color-foreground-subtlest,#87888f)}
.ss-wt-badge{flex:none;font-size:11px;line-height:1.2;padding:0 4px;border-radius:4px;white-space:nowrap}
.ss-wt-badge--merged{color:#2dd4bf;background:rgba(45,212,191,.12)}
.ss-wt-badge--dirty{color:#f59e0b;background:rgba(245,158,11,.14)}
.ss-row-actions{flex:none;display:inline-flex;align-items:center;gap:3px}
.ss-row-action{border:0;background:none;padding:1px 5px;border-radius:4px;font:inherit;font-size:11px;color:var(--color-foreground-subtlest,#87888f);cursor:pointer}
.ss-row-action--cancel,.ss-row-action--archive{opacity:0;transition:opacity .12s ease}
.ss-child-row:hover .ss-row-action--cancel,.ss-child-row:hover .ss-row-action--archive,
.ss-child-row:focus-within .ss-row-action--cancel,.ss-child-row:focus-within .ss-row-action--archive{opacity:1}
.ss-row-action:hover:not(:disabled){background:var(--color-surface-hover);color:var(--color-foreground)}
.ss-row-action:disabled{opacity:.45;cursor:not-allowed}
.ss-row-action--respond{opacity:1;padding:1px 6px;border:1px solid rgba(245,158,11,.42);background:rgba(245,158,11,.14);
  color:#f59e0b;font-weight:500;white-space:nowrap}
.ss-row-action--respond:hover:not(:disabled){background:rgba(245,158,11,.24);color:#fbbf24}
.ss-action-err-pill{flex:none;padding:0 5px;border-radius:4px;font-size:10.5px;color:var(--color-destructive,#ef4444);
  background:rgba(239,68,68,.14);white-space:nowrap;animation:ss-err-flash .35s ease 2}
@keyframes ss-err-flash{0%,100%{opacity:1}50%{opacity:.3}}
#ss-overlay-root{position:fixed;top:56px;left:280px;right:auto;pointer-events:none;z-index:40;display:flex;justify-content:center}
#ss-overlay-root[hidden]{display:none!important}
.ss-parent-banner{pointer-events:auto;display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:9999px;
  border:1px solid var(--color-border,#8884);background:var(--color-surface,#1f2024);color:var(--color-foreground);
  font:inherit;font-size:12px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.18)}
.ss-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
`;

  const ACTION_TIMEOUT_MS = 15000;
  const ACTION_ERROR_TTL_MS = 8000;
  const COPY_FEEDBACK_MS = 1500;

  // ---------- 状态 ----------
  let snap = null;
  let bySid = new Map();
  let byNodeId = new Map();
  let kids = new Map();
  let mo = null;
  let overlayRo = null;
  let observedChatEl = null;
  let observedHeaderEl = null;
  let tick = null;
  let raf = 0;
  let lastActive = null;
  let lastActiveSig = '';
  let lastViewportSig = '';
  let lastError = null;
  let lastNav = null;
  let dedupStates = [];
  const actionQueue = []; // [{ actionId, kind, nodeId, expectedRevision?, runId?, reason? }]
  const inflightActionByNode = new Map(); // nodeId -> actionId
  const actionQueuedAtById = new Map(); // actionId -> timestampMs
  const lastActionErrorByNode = new Map(); // nodeId -> { code, message, until }
  const copiedWaitUntilByNode = new Map(); // nodeId -> untilMs
  const auxTimers = new Set();
  const restore = []; // [{el, attr, prevValue|null}] 仅记录本插件改过的宿主属性
  const memCollapse = new Map();
  const hosts = new Map(); // instanceKey -> host element
  const decoratedParents = new Map(); // instanceKey -> { row, titleSlot }

  function scheduleAuxTimer(fn, ms) {
    if (typeof setTimeout !== 'function') return 0;
    const tid = setTimeout(() => {
      auxTimers.delete(tid);
      if (api.alive) fn();
    }, ms);
    auxTimers.add(tid);
    return tid;
  }

  function clearAuxTimers() {
    for (const tid of auxTimers) {
      clearTimeout(tid);
    }
    auxTimers.clear();
  }

  function pruneExpiredState(nowMs = Date.now()) {
    let changed = false;
    const liveIds = new Set();
    for (let i = actionQueue.length - 1; i >= 0; i--) {
      const a = actionQueue[i];
      const qAt = actionQueuedAtById.get(a.actionId) || 0;
      if (nowMs - qAt >= ACTION_TIMEOUT_MS) {
        actionQueue.splice(i, 1);
        actionQueuedAtById.delete(a.actionId);
        if (inflightActionByNode.get(a.nodeId) === a.actionId) {
          inflightActionByNode.delete(a.nodeId);
        }
        changed = true;
      } else {
        liveIds.add(a.actionId);
      }
    }
    for (const [nid, aid] of [...inflightActionByNode.entries()]) {
      const qAt = actionQueuedAtById.get(aid) || 0;
      if (!liveIds.has(aid) || nowMs - qAt >= ACTION_TIMEOUT_MS) {
        inflightActionByNode.delete(nid);
        actionQueuedAtById.delete(aid);
        changed = true;
      }
    }
    for (const [nid, err] of [...lastActionErrorByNode.entries()]) {
      if (!err || nowMs >= err.until) {
        lastActionErrorByNode.delete(nid);
        changed = true;
      }
    }
    for (const [nid, until] of [...copiedWaitUntilByNode.entries()]) {
      if (nowMs >= until) {
        copiedWaitUntilByNode.delete(nid);
        changed = true;
      }
    }
    return changed;
  }

  function getActiveActionError(nodeId) {
    const err = lastActionErrorByNode.get(nodeId);
    if (!err) return null;
    if (Date.now() >= err.until) {
      lastActionErrorByNode.delete(nodeId);
      return null;
    }
    return err;
  }

  function newActionId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, ch => {
      const r = (Math.random() * 16) | 0;
      const v = ch === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  function enqueueAction(kind, nodeId) {
    pruneExpiredState();
    const live = byNodeId.get(nodeId);
    if (!live || inflightActionByNode.has(nodeId)) return null;
    if (actionQueue.length >= 16) return null;
    const actionId = newActionId();
    let item = null;
    if (kind === 'archive_session') {
      if (!live.canArchive) return null;
      item = {
        actionId,
        kind: 'archive_session',
        nodeId: live.nodeId,
        expectedRevision: Number(live.revision || 1),
      };
    } else if (kind === 'cancel_run') {
      if (!live.canCancel || !live.activeRunId) return null;
      item = {
        actionId,
        kind: 'cancel_run',
        nodeId: live.nodeId,
        runId: String(live.activeRunId),
        reason: 'cancelled from sidebar UI',
      };
    } else {
      return null;
    }
    actionQueue.push(item);
    actionQueuedAtById.set(actionId, Date.now());
    inflightActionByNode.set(nodeId, actionId);
    scheduleAuxTimer(() => {
      if (pruneExpiredState()) schedule();
    }, ACTION_TIMEOUT_MS + 50);
    schedule();
    return item;
  }

  function drainActions() {
    pruneExpiredState();
    return actionQueue.slice(0, 16).map(a => ({ ...a }));
  }

  function ackActions(receipts) {
    pruneExpiredState();
    if (!Array.isArray(receipts)) return { acked: 0, remaining: actionQueue.length };
    const queuedNodeByActionId = new Map(actionQueue.map(a => [a.actionId, a.nodeId]));
    for (const [nid, aid] of inflightActionByNode.entries()) {
      if (!queuedNodeByActionId.has(aid)) queuedNodeByActionId.set(aid, nid);
    }
    const ackedIds = new Set();
    const nowMs = Date.now();
    let hasError = false;
    for (const r of receipts) {
      if (!r || typeof r !== 'object') continue;
      const rawId = r.actionId || r.action_id || r.request_id;
      const aid = rawId ? String(rawId) : null;
      if (aid) ackedIds.add(aid);
      const targetNodeId = r.nodeId || r.node_id || (aid ? queuedNodeByActionId.get(aid) : null);
      if (targetNodeId) {
        const nidStr = String(targetNodeId);
        if (r.ok === false) {
          lastActionErrorByNode.set(nidStr, {
            code: String(r.code || 'ACTION_FAILED'),
            message: String(r.message || r.code || '操作失败'),
            until: nowMs + ACTION_ERROR_TTL_MS,
          });
          hasError = true;
        } else if (r.ok === true) {
          lastActionErrorByNode.delete(nidStr);
        }
      }
    }
    if (hasError) {
      scheduleAuxTimer(() => {
        if (pruneExpiredState()) schedule();
      }, ACTION_ERROR_TTL_MS + 50);
    }
    if (!ackedIds.size) {
      if (hasError) schedule();
      return { acked: 0, remaining: actionQueue.length };
    }
    let acked = 0;
    for (let i = actionQueue.length - 1; i >= 0; i--) {
      if (ackedIds.has(actionQueue[i].actionId)) {
        const removed = actionQueue.splice(i, 1)[0];
        actionQueuedAtById.delete(removed.actionId);
        if (inflightActionByNode.get(removed.nodeId) === removed.actionId) {
          inflightActionByNode.delete(removed.nodeId);
        }
        acked++;
      }
    }
    for (const [nid, aid] of inflightActionByNode.entries()) {
      if (ackedIds.has(aid)) {
        inflightActionByNode.delete(nid);
        actionQueuedAtById.delete(aid);
      }
    }
    schedule();
    return { acked, remaining: actionQueue.length };
  }

  const sidOf = n => (n && (n.runtimeSessionId || n.sessionId)) || null;

  const collapseKey = n =>
    `ss.sidebar-tree.v1:${snap ? snap.storeInstanceId : ''}:${n.hostId}|${n.workspaceIdentity || ''}|${n.workspacePath}|${sidOf(n) || ''}`;

  function isCollapsed(n) {
    const k = collapseKey(n);
    try {
      const v = localStorage.getItem(k);
      if (v !== null) return v === '1';
    } catch (_) {}
    return memCollapse.get(k) === true; // 默认展开
  }

  function setCollapsed(n, c) {
    const k = collapseKey(n);
    memCollapse.set(k, c);
    try {
      if (c) localStorage.setItem(k, '1');
      else localStorage.removeItem(k);
    } catch (_) {}
  }

  function statusOf(n) {
    const s = n.executionState;
    const o = n.lastOutcome;
    if (s === 'waiting_input') return 'waiting';
    if (s === 'queued' || s === 'starting' || s === 'running' || s === 'stopping') return 'running';
    if (s === 'failed' || o === 'failed' || o === 'blocked') return 'error';
    if (s === 'exited' && o === 'success') return 'done';
    return 'none';
  }

  function isSelectedChild(n, activeTaskId, isWorkspaceActive = true) {
    const childSid = sidOf(n);
    return Boolean(isWorkspaceActive !== false && activeTaskId && childSid && activeTaskId === childSid);
  }

  function isWaitingWithId(n) {
    return Boolean((n.waitingInput || (n.comm && n.comm.waitingInput)) && n.activeWaitId);
  }

  function sig(n, activeTaskId, isWorkspaceActive = true) {
    const ch = (kids.get(n.nodeId) || []).map(c => sig(c, activeTaskId, isWorkspaceActive)).join(',');
    const c = n.comm || {};
    const selected = isSelectedChild(n, activeTaskId, isWorkspaceActive);
    const inflight = inflightActionByNode.has(n.nodeId);
    const actErr = getActiveActionError(n.nodeId);
    const errSig = actErr ? `${actErr.code}:${actErr.until}` : '';
    const copiedSig = (copiedWaitUntilByNode.get(n.nodeId) || 0) > Date.now() ? '1' : '0';
    return `${n.nodeId}|${n.revision || 0}|${n.title}|${n.name}|${statusOf(n)}|${n.indexState}|${selected}|${isCollapsed(n)}|${n.activeRunId || ''}|${Boolean(n.waitingInput || c.waitingInput)}|${n.activeWaitId || ''}|${n.waitingInputKind || ''}|${Boolean(n.canArchive)}|${Boolean(n.canCancel)}|${n.branchName || ''}|${n.worktreeState || ''}|${Boolean(n.canResumeForIndex)}|${inflight}|${errSig}|${copiedSig}|${c.commSignature || ''}|[${ch}]`;
  }

  function setAttrTracked(el, attr, val) {
    if (!restore.some(r => r.el === el && r.attr === attr)) {
      restore.push({ el, attr, prevValue: el.getAttribute(attr) });
    }
    el.setAttribute(attr, val);
  }

  function restoreAttrTracked(el, attr) {
    if (!el) return;
    for (let i = restore.length - 1; i >= 0; i--) {
      if (restore[i].el === el && restore[i].attr === attr) {
        const prevValue = restore[i].prevValue;
        if (prevValue === null) el.removeAttribute(attr);
        else el.setAttribute(attr, prevValue);
        restore.splice(i, 1);
        return;
      }
    }
    el.removeAttribute(attr);
  }

  function cleanupParentDecoration(row, titleSlot) {
    if (titleSlot) {
      if (typeof titleSlot.querySelectorAll === 'function') {
        titleSlot
          .querySelectorAll(':scope > .ss-tree-chevron, :scope > .ss-comm-badge--parent, :scope > [data-ss-parent-badge]')
          .forEach(el => el.remove());
      }
      if (Array.isArray(titleSlot.children)) {
        for (const ch of [...titleSlot.children]) {
          if (
            ch &&
            typeof ch.getAttribute === 'function' &&
            (ch.hasAttribute(OWN) || ch.hasAttribute('data-ss-parent-badge'))
          ) {
            if (typeof ch.remove === 'function') ch.remove();
          }
        }
      }
    }
    if (row) {
      restoreAttrTracked(row, 'data-ss-has-children');
    }
  }

  // ---------- 渲染 ----------
  function mk(tag, cls, props) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (props) Object.assign(e, props);
    e.setAttribute(OWN, '1');
    return e;
  }

  function chevron(n, controlsId) {
    const b = mk('button', 'ss-tree-chevron', { type: 'button', textContent: '⌄' });
    b.draggable = false;
    b.setAttribute('aria-controls', controlsId);
    const sync = () => {
      const ex = !isCollapsed(n);
      b.setAttribute('aria-expanded', String(ex));
      b.title = ex ? '折叠子会话' : '展开子会话';
    };
    sync();
    const stop = e => {
      e.stopPropagation();
    };
    b.addEventListener('pointerdown', stop);
    b.addEventListener('mousedown', stop);
    b.addEventListener('click', e => {
      e.stopPropagation();
      e.preventDefault();
      setCollapsed(n, !isCollapsed(n));
      schedule();
    });
    b.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.stopPropagation();
        e.preventDefault();
        setCollapsed(n, !isCollapsed(n));
        schedule();
      }
    });
    b._ssSync = sync;
    return b;
  }

  function commBadge(n) {
    const c = n.comm || {};
    const el = mk('span', 'ss-comm-badge');
    if (c.toParentUnread > 0) {
      el.append(mk('span', 'ss-dot'), document.createTextNode(String(c.toParentUnread)));
    }
    if (c.waitingInput) el.append(document.createTextNode('待审批'));
    if (c.toChildQueued > 0) el.append(mk('span', 'ss-dot hollow'));
    const tips = [];
    if (c.lastToParent && c.lastToParent.recapPreview) tips.push(c.lastToParent.recapPreview);
    if (n.reportPendingAck) tips.push('报告待父会话处理');
    if (c.idleParentHint) tips.push('下次发言时注入');
    if (tips.length) el.title = tips.join('\n'); // 只用 title/textContent，禁止 innerHTML
    return el;
  }

  function worktreeBadge(n) {
    if (n.worktreeState === 'merged') {
      return mk('span', 'ss-wt-badge ss-wt-badge--merged', { textContent: '已合并' });
    }
    if (n.worktreeState === 'retained_dirty') {
      return mk('span', 'ss-wt-badge ss-wt-badge--dirty', { textContent: '脏目录保留' });
    }
    return null;
  }

  async function copyTextWithFallback(text) {
    try {
      if (
        typeof navigator !== 'undefined' &&
        navigator.clipboard &&
        typeof navigator.clipboard.writeText === 'function'
      ) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    try {
      if (typeof document !== 'undefined' && typeof document.createElement === 'function') {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.setAttribute(OWN, '1');
        if (ta.style) {
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          ta.style.left = '-9999px';
        }
        const mountParent = document.body || document.documentElement;
        if (mountParent && typeof mountParent.append === 'function') mountParent.append(ta);
        if (typeof ta.focus === 'function') ta.focus();
        if (typeof ta.select === 'function') ta.select();
        const ok = typeof document.execCommand === 'function' ? Boolean(document.execCommand('copy')) : false;
        if (typeof ta.remove === 'function') ta.remove();
        return ok;
      }
    } catch (_) {}
    return false;
  }

  function formatErrorTip(actErr) {
    if (!actErr) return '';
    return actErr.message && actErr.message !== actErr.code
      ? `操作失败 [${actErr.code}]：${actErr.message}`
      : `操作失败：${actErr.code}`;
  }

  function rowActionButtons(n) {
    const hasWait = isWaitingWithId(n);
    const hasCancel = Boolean(n.canCancel && n.activeRunId);
    const hasArchive = Boolean(n.canArchive);
    const actErr = getActiveActionError(n.nodeId);
    if (!hasWait && !hasCancel && !hasArchive && !actErr) return null;

    const wrap = mk('span', 'ss-row-actions');
    const isBusy = inflightActionByNode.has(n.nodeId);
    const errTip = formatErrorTip(actErr);

    if (actErr) {
      wrap.append(
        mk('span', 'ss-action-err-pill', {
          textContent: actErr.code,
          title: errTip,
        })
      );
    }

    if (hasWait) {
      const defaultWaitLabel = n.waitingInputKind === 'permission' ? '批权限' : '回问题';
      const isCopied = (copiedWaitUntilByNode.get(n.nodeId) || 0) > Date.now();
      const waitCmd = '/side-sessions:respond ' + n.activeWaitId + ' ';
      const waitBtn = mk('button', 'ss-row-action ss-row-action--respond', {
        type: 'button',
        textContent: isCopied ? '已复制 ✓' : defaultWaitLabel,
        title: `复制回复令：${waitCmd.trim()}`,
      });
      waitBtn.draggable = false;
      waitBtn.setAttribute('data-ss-action', 'copy_respond');
      const stop = e => {
        e.stopPropagation();
      };
      const handleCopy = e => {
        e.stopPropagation();
        e.preventDefault();
        copyTextWithFallback(waitCmd).then(ok => {
          if (!ok) return;
          copiedWaitUntilByNode.set(n.nodeId, Date.now() + COPY_FEEDBACK_MS);
          waitBtn.textContent = '已复制 ✓';
          scheduleAuxTimer(() => {
            copiedWaitUntilByNode.delete(n.nodeId);
            if (waitBtn.isConnected) waitBtn.textContent = defaultWaitLabel;
            schedule();
          }, COPY_FEEDBACK_MS);
        });
      };
      waitBtn.addEventListener('pointerdown', stop);
      waitBtn.addEventListener('mousedown', stop);
      waitBtn.addEventListener('click', handleCopy);
      waitBtn.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          handleCopy(e);
        }
      });
      wrap.append(waitBtn);
    }

    const makeBtn = (kind, label, baseTitle) => {
      const fullTitle = errTip ? `${baseTitle}\n${errTip}` : baseTitle;
      const b = mk('button', `ss-row-action ss-row-action--${kind === 'cancel_run' ? 'cancel' : 'archive'}`, {
        type: 'button',
        textContent: label,
        title: fullTitle,
        disabled: isBusy,
      });
      b.draggable = false;
      b.setAttribute('data-ss-action', kind);
      const stop = e => {
        e.stopPropagation();
      };
      const trigger = e => {
        e.stopPropagation();
        e.preventDefault();
        if (b.disabled) return;
        const queued = enqueueAction(kind, n.nodeId);
        if (queued) {
          b.disabled = true;
        }
      };
      b.addEventListener('pointerdown', stop);
      b.addEventListener('mousedown', stop);
      b.addEventListener('click', trigger);
      b.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          trigger(e);
        }
      });
      return b;
    };
    if (hasCancel) {
      wrap.append(makeBtn('cancel_run', '取消', '取消当前运行回合'));
    }
    if (hasArchive) {
      wrap.append(makeBtn('archive_session', '归档', '归档该子会话'));
    }
    return wrap;
  }

  function renderList(ul, list, activeTaskId, isWorkspaceActive = true, instPrefix = '') {
    const keep = new Map([...ul.children].map(li => [li.getAttribute('data-ss-node-id'), li]));
    const frag = [];
    for (const n of list) {
      let li = keep.get(n.nodeId);
      const s = sig(n, activeTaskId, isWorkspaceActive);
      const subId = instPrefix ? `ss-sub-${instPrefix}-${n.nodeId}` : `ss-sub-${n.nodeId}`;
      if (!li || li._ssSig !== s) {
        const fresh = mk('li', 'ss-child-item');
        fresh.setAttribute('data-ss-node-id', n.nodeId);
        const row = mk('div', 'ss-child-row');
        const btn = mk('button', 'ss-child-link', { type: 'button' });
        btn.draggable = false;
        btn.setAttribute('data-status', statusOf(n));
        if (isSelectedChild(n, activeTaskId, isWorkspaceActive)) {
          btn.setAttribute('aria-current', 'page');
        } else {
          btn.removeAttribute('aria-current');
        }
        if (n.indexState !== 'indexed' && !n.cliExists) btn.setAttribute('data-nav', 'pending');
        const actErr = getActiveActionError(n.nodeId);
        const branchTip = n.branchName
          ? ` | 分支: ${n.branchName}${n.worktreeState ? ' (' + n.worktreeState + ')' : ''}`
          : '';
        const baseRowTitle = `${n.title || n.name} (${n.name})${branchTip}`;
        btn.title = actErr ? `${baseRowTitle}\n${formatErrorTip(actErr)}` : baseRowTitle;
        const st = mk('span', 'ss-status');
        st.setAttribute('data-s', statusOf(n));
        btn.append(
          st,
          mk('span', 'ss-child-title', { textContent: n.title || n.name }),
          mk('span', 'ss-child-handle', { textContent: `(${n.name})` }),
          commBadge(n)
        );
        const wtBadge = worktreeBadge(n);
        if (wtBadge) btn.append(wtBadge);
        btn.addEventListener('click', e => {
          e.stopPropagation();
          openChild(n, btn);
        });
        btn.addEventListener('keydown', e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            e.stopPropagation();
            openChild(n, btn);
          }
        });
        const childList = kids.get(n.nodeId) || [];
        if (childList.length) row.append(chevron(n, subId));
        row.append(btn);
        const actBtns = rowActionButtons(n);
        if (actBtns) row.append(actBtns);
        fresh.append(row);
        if (childList.length) {
          const sub = mk('ul', 'ss-child-list');
          sub.id = subId;
          sub.hidden = isCollapsed(n);
          renderList(sub, childList, activeTaskId, isWorkspaceActive, instPrefix);
          fresh.append(sub);
        }
        fresh._ssSig = s;
        const hadFocus = li && li.contains(document.activeElement);
        li = fresh;
        if (hadFocus) {
          queueMicrotask(() => {
            const link = li.querySelector('.ss-child-link');
            if (link) link.focus();
          });
        }
      }
      frag.push(li);
    }
    ul.replaceChildren(...frag);
  }

  async function openChild(n, btn) {
    btn.setAttribute('data-nav', 'pending');
    let res;
    try {
      res = await A.navigate(sidOf(n), n.workspacePath, n);
    } catch (e) {
      res = { ok: false, code: 'NAV_EXCEPTION', message: String(e) };
    }
    if (res && (res.reason === 'SUPERSEDED' || res.code === 'SUPERSEDED')) {
      if (n.indexState === 'indexed' || n.cliExists) {
        btn.removeAttribute('data-nav');
      }
      return res;
    }
    lastNav = res;
    if (res && res.ok) {
      btn.removeAttribute('data-nav');
    } else if (n.indexState === 'indexed' || n.cliExists) {
      btn.removeAttribute('data-nav');
    }
    if (!res || !res.ok) btn.title = `无法打开：${(res && (res.code || res.reason)) || 'UNKNOWN'}`;
    return res;
  }

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = mk('style', null, { id: STYLE_ID, textContent: CSS });
    (document.head || document.documentElement).append(s);
  }

  function sumUnread(n) {
    const treeSum = (kids.get(n.nodeId) || []).reduce(
      (a, c) => a + ((c.comm && c.comm.toParentUnread) || 0) + sumUnread(c),
      0
    );
    const projTotal =
      typeof n.childrenUnreadTotal === 'number'
        ? n.childrenUnreadTotal
        : (n.comm && typeof n.comm.childrenUnreadTotal === 'number' ? n.comm.childrenUnreadTotal : 0);
    return Math.max(treeSum, projTotal);
  }

  function commBadgeParent(n) {
    const el = mk('span', 'ss-comm-badge ss-comm-badge--parent');
    el.setAttribute('data-ss-parent-badge', '');
    const u = sumUnread(n);
    if (u) el.append(mk('span', 'ss-dot'), document.createTextNode(String(u)));
    return el;
  }

  function readGlobalActive(mounts) {
    if (!A) return { activeTaskId: null, sig: '' };
    let activeTaskId = null;
    const parts = [];
    for (const m of mounts || []) {
      const st = (A.readActive && A.readActive(m)) || {};
      const isAct = st.isWorkspaceActive !== false;
      if (isAct && st.activeTaskId && !activeTaskId) {
        activeTaskId = st.activeTaskId;
      }
      parts.push(`${m.instanceKey}:${isAct ? 1 : 0}:${st.activeTaskId || ''}`);
    }
    if (!activeTaskId && typeof A.readActiveConversationId === 'function') {
      activeTaskId = A.readActiveConversationId(mounts) || null;
    }
    parts.push(`fb:${activeTaskId || ''}`);
    return { activeTaskId, sig: parts.join('|') };
  }

  function resolveCurrentViewport() {
    if (typeof document === 'undefined') return null;
    if (A && typeof A.resolveChatViewport === 'function') {
      return A.resolveChatViewport();
    }
    const chatEl = document.querySelector((A && A.SEL && A.SEL.chatView) || '[data-testid="chat-view"]');
    if (!chatEl || chatEl.hidden) return null;
    const rect = typeof chatEl.getBoundingClientRect === 'function' ? chatEl.getBoundingClientRect() : null;
    if (!rect || !(typeof rect.width === 'number' && rect.width > 0)) return null;
    if (typeof rect.height === 'number' && rect.height <= 0) return null;
    return {
      el: chatEl,
      headerEl: null,
      top: Math.round(rect.top || 0),
      left: Math.round(rect.left || 0),
      width: Math.round(rect.width),
    };
  }

  function setInlineStyle(el, prop, value) {
    el.style[prop] = value;
    if (typeof el.style.setProperty === 'function') {
      el.style.setProperty(prop, value);
    }
  }

  function syncOverlayBanner() {
    if (typeof document === 'undefined') return;
    let overlay = document.getElementById('ss-overlay-root');
    const activeChild = lastActive ? bySid.get(lastActive) : null;
    const parentNode =
      activeChild && activeChild.parentNodeId ? byNodeId.get(activeChild.parentNodeId) : null;

    if (!activeChild || !parentNode) {
      lastViewportSig = 'inactive';
      if (overlay) {
        overlay.replaceChildren();
        overlay.hidden = true;
      }
      return;
    }

    const vp = resolveCurrentViewport();
    if (!vp) {
      lastViewportSig = 'hidden';
      if (overlayRo) {
        try {
          overlayRo.disconnect();
        } catch (_) {}
        overlayRo = null;
      }
      observedChatEl = null;
      observedHeaderEl = null;
      if (overlay) {
        overlay.replaceChildren();
        overlay.hidden = true;
      }
      return;
    }

    lastViewportSig = `${vp.top}:${vp.left}:${vp.width}`;

    if (!overlay) {
      overlay = mk('div', null, { id: 'ss-overlay-root' });
      const mountParent = document.body || document.documentElement || document.head;
      if (mountParent) mountParent.append(overlay);
    }

    if (vp.el !== observedChatEl || (vp.headerEl || null) !== observedHeaderEl) {
      if (overlayRo) {
        try {
          overlayRo.disconnect();
        } catch (_) {}
        overlayRo = null;
      }
      observedChatEl = vp.el;
      observedHeaderEl = vp.headerEl || null;
      if (typeof ResizeObserver === 'function' && observedChatEl) {
        overlayRo = new ResizeObserver(() => {
          if (api.alive) syncOverlayBanner();
        });
        overlayRo.observe(observedChatEl);
        if (observedHeaderEl) overlayRo.observe(observedHeaderEl);
      }
    }

    setInlineStyle(overlay, 'top', (vp.top + 8) + 'px');
    setInlineStyle(overlay, 'left', (vp.left + 16) + 'px');
    setInlineStyle(overlay, 'width', Math.max(200, vp.width - 32) + 'px');
    setInlineStyle(overlay, 'right', 'auto');

    const unreadN = sumUnread(parentNode);
    const parts = [`← 返回母对话：${parentNode.title || parentNode.name}`, `(${activeChild.name})`];
    if (activeChild.branchName) {
      parts.push(`⎇ ${activeChild.branchName}`);
    }
    if (unreadN > 0) {
      parts.push(`母对话有 ${unreadN} 条未读汇报 · 点击返回处理`);
    }
    const labelText = parts.join(' ');
    overlay.hidden = false;
    const btn = mk('button', 'ss-parent-banner', {
      type: 'button',
      textContent: labelText,
    });
    btn.addEventListener('click', e => {
      e.stopPropagation();
      e.preventDefault();
      A.navigate(sidOf(parentNode), parentNode.workspacePath, parentNode);
    });
    overlay.replaceChildren(btn);
  }

  function reconcile() {
    raf = 0;
    if (!api.alive || !snap || !A) return;
    try {
      pruneExpiredState();
      ensureStyle();
      const mounts = A.findTaskMounts();
      const globalAct = readGlobalActive(mounts);
      lastActive = globalAct.activeTaskId;
      lastActiveSig = globalAct.sig;
      const seen = new Set();
      const byTR = new Map();
      for (const m of mounts) {
        if (!byTR.has(m.trFiber)) byTR.set(m.trFiber, []);
        byTR.get(m.trFiber).push(m);
        const node = bySid.get(m.taskId);
        const children = node ? kids.get(node.nodeId) || [] : [];
        if (!node || !children.length || m.hostId !== 'local') {
          cleanupParentDecoration(m.row, m.titleSlot);
          continue;
        }
        seen.add(m.instanceKey);
        decoratedParents.set(m.instanceKey, { row: m.row, titleSlot: m.titleSlot });
        const mAct = (A.readActive && A.readActive(m)) || {};
        const isWorkspaceActive = mAct.isWorkspaceActive !== false;
        const mountActiveTaskId = isWorkspaceActive ? mAct.activeTaskId ?? null : null;
        // 1) 父行箭头与父行未读合计徽章
        const hostId = `ss-tree-${m.instanceKey.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
        setAttrTracked(m.row, 'data-ss-has-children', 'true');
        if (m.titleSlot && !m.titleSlot.querySelector(':scope > .ss-tree-chevron')) {
          m.titleSlot.append(chevron(node, hostId));
        }
        if (m.titleSlot) {
          m.titleSlot.querySelectorAll(':scope > .ss-tree-chevron').forEach(b => b._ssSync && b._ssSync());
          const oldBadge = m.titleSlot.querySelector(
            ':scope > .ss-comm-badge--parent, :scope > [data-ss-parent-badge]'
          );
          const badge = commBadgeParent(node);
          if (oldBadge) oldBadge.replaceWith(badge);
          else m.titleSlot.append(badge);
        }
        // 2) host 挂在 OCt wrapper 末尾（wCt 根节点之后）
        let host = hosts.get(m.instanceKey);
        if (!host || !host.isConnected || host.parentElement !== m.wrapper) {
          host = mk('div');
          host.id = hostId;
          host.setAttribute('data-ss-tree-host', m.instanceKey);
          host.append(mk('ul', 'ss-child-list'), mk('span', 'ss-sr', { ariaLive: 'polite' }));
          hosts.set(m.instanceKey, host);
        }
        if (m.wrapper.lastElementChild !== host) m.wrapper.appendChild(host);
        if (m.titleText) {
          const d = m.titleText.getBoundingClientRect().left - m.wrapper.getBoundingClientRect().left;
          host.style.setProperty('--ss-indent', (d > 0 && d < 120 ? d : 26) + 'px');
        }
        host.hidden = isCollapsed(node);
        renderList(host.querySelector('ul'), children, mountActiveTaskId, isWorkspaceActive, hostId);
        const unread = sumUnread(node);
        const sr = host.querySelector('.ss-sr');
        const nextSrText = unread ? `${unread} 条子会话报告待处理` : '';
        if (sr && sr.textContent !== nextSrText) {
          sr.textContent = nextSrText;
        }
      }
      for (const [k, info] of decoratedParents) {
        if (!seen.has(k)) {
          cleanupParentDecoration(info.row, info.titleSlot);
          decoratedParents.delete(k);
        }
      }
      for (const [k, h] of hosts) {
        if (!seen.has(k)) {
          h.remove();
          hosts.delete(k);
        }
      }
      // 3) 去重（逐个 tR）
      dedupStates = [...byTR.values()].map(ms => A.suppressDuplicates(ms, bySid, byNodeId));
      syncOverlayBanner();
      lastError = null;
    } catch (e) {
      lastError = String((e && e.stack) || e);
    }
  }

  function schedule() {
    if (!api.alive || raf) return;
    if (typeof document !== 'undefined' && document.hidden) {
      raf = setTimeout(reconcile, 1000);
      return;
    }
    const rAF = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : fn => setTimeout(fn, 16);
    raf = -1;
    const id = rAF(reconcile);
    if (raf === -1) raf = id || 1;
  }

  // ---------- 生命周期 ----------
  let navRoot = null;
  let onPointerDown = null;
  let onDragStart = null;
  let armed = false;

  function isOwnedNode(node) {
    if (!node) return false;
    const el = node.nodeType === 1 ? node : node.parentElement;
    return !!(
      el &&
      (el.getAttribute(OWN) === '1' || el.hasAttribute(OWN) || (el.closest && el.closest(`[${OWN}]`)))
    );
  }

  function bindRoot() {
    const r = A && A.resolveSidebarRoot();
    if (r === navRoot) return;
    unbindRoot();
    navRoot = r;
    if (!r) return;
    mo = new MutationObserver(muts => {
      for (const m of muts) {
        if (isOwnedNode(m.target)) continue;
        const nodes = [...m.addedNodes, ...m.removedNodes];
        if (nodes.length && nodes.every(isOwnedNode)) {
          continue;
        }
        schedule();
        return;
      }
    });
    mo.observe(r, { childList: true, subtree: true });
    // 拖拽隔离：dragstart 的 target 是 draggable 的 li，按钮上的 draggable=false 拦不住（复核 #5-2）
    onPointerDown = e => {
      armed = !!(
        typeof Element !== 'undefined' &&
        e.target instanceof Element &&
        e.target.closest('.ss-tree-chevron,[data-ss-tree-host]')
      );
    };
    onDragStart = e => {
      if (armed) {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    r.addEventListener('pointerdown', onPointerDown, true);
    r.addEventListener('dragstart', onDragStart, true);
  }

  function unbindRoot() {
    if (mo) mo.disconnect();
    mo = null;
    if (navRoot && onPointerDown) {
      navRoot.removeEventListener('pointerdown', onPointerDown, true);
      navRoot.removeEventListener('dragstart', onDragStart, true);
    }
    navRoot = null;
  }

  const onStorage = e => {
    if (e.key && e.key.startsWith('ss.sidebar-tree.v1:')) schedule();
  };

  const onResize = () => {
    if (api.alive) syncOverlayBanner();
  };

  function start() {
    if (!api.alive) return;
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', onStorage);
      window.addEventListener('resize', onResize);
    }
    tick = setInterval(() => {
      if (!api.alive) return;
      bindRoot();
      const pruned = pruneExpiredState();
      const ms = A ? A.findTaskMounts() : [];
      const curAct = readGlobalActive(ms);
      if (pruned || curAct.sig !== lastActiveSig) {
        schedule();
        return;
      }
      if (lastActive) {
        const vp = resolveCurrentViewport();
        const vpSig = vp ? `${vp.top}:${vp.left}:${vp.width}` : 'hidden';
        if (vpSig !== lastViewportSig) syncOverlayBanner();
      }
    }, 400);
    bindRoot();
    schedule();
  }

  const api = {
    version: VERSION,
    alive: true,
    update(next) {
      if (!next || next.schemaVersion !== 1) return { ok: false, code: 'BAD_SCHEMA' };
      if (snap && next.projectionRevision === snap.projectionRevision) return { ok: true, unchanged: true };
      snap = next;
      bySid = new Map();
      byNodeId = new Map();
      kids = new Map();
      for (const n of next.nodes || []) {
        byNodeId.set(n.nodeId, n);
        const sid = sidOf(n);
        if (sid) bySid.set(sid, n);
        if (n.sessionId) bySid.set(n.sessionId, n);
        if (n.runtimeSessionId) bySid.set(n.runtimeSessionId, n);
      }
      for (const n of next.nodes || []) {
        if (!n.parentNodeId || n.archived || n.nodeStatus === 'archived') continue;
        const p = byNodeId.get(n.parentNodeId);
        if (!p || p.archived || p.nodeStatus === 'archived') continue;
        if (!kids.has(n.parentNodeId)) kids.set(n.parentNodeId, []);
        kids.get(n.parentNodeId).push(n);
      }
      for (const l of kids.values()) {
        l.sort((a, b) =>
          a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.nodeId < b.nodeId ? -1 : 1
        );
      }
      schedule();
      return { ok: true };
    },
    enqueueAction,
    drainActions,
    ackActions,
    getStatus() {
      pruneExpiredState();
      const sc = A ? A.selfCheck() : {};
      return {
        alive: Boolean(api.alive),
        version: VERSION,
        adapterId: A && A.id,
        ...sc,
        projectionRevision: snap && snap.projectionRevision,
        mountedParentCount: hosts.size,
        childCount: snap ? (snap.nodes || []).filter(n => n.parentNodeId).length : 0,
        activeTaskId: lastActive,
        pendingActions: actionQueue.length,
        dedup: dedupStates.map(d => d.state),
        lastNav,
        lastError,
      };
    },
    destroy() {
      api.alive = false;
      clearInterval(tick);
      tick = null;
      clearAuxTimers();
      if (raf) {
        if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(raf);
        clearTimeout(raf);
        raf = 0;
      }
      if (overlayRo) {
        try {
          overlayRo.disconnect();
        } catch (_) {}
        overlayRo = null;
      }
      observedChatEl = null;
      observedHeaderEl = null;
      actionQueue.length = 0;
      inflightActionByNode.clear();
      actionQueuedAtById.clear();
      lastActionErrorByNode.clear();
      copiedWaitUntilByNode.clear();
      unbindRoot();
      if (typeof window !== 'undefined') {
        window.removeEventListener('storage', onStorage);
        window.removeEventListener('resize', onResize);
      }
      if (typeof document !== 'undefined') {
        document.removeEventListener('DOMContentLoaded', start);
      }
      try {
        if (A && A.restoreDedup) A.restoreDedup();
      } catch (_) {}
      for (const info of decoratedParents.values()) {
        cleanupParentDecoration(info.row, info.titleSlot);
      }
      decoratedParents.clear();
      if (typeof document !== 'undefined') {
        const ov = document.getElementById('ss-overlay-root');
        if (ov && typeof ov.remove === 'function') ov.remove();
        document.querySelectorAll(`[${OWN}]`).forEach(e => e.remove());
      }
      for (const r of restore) {
        if (r.prevValue === null) r.el.removeAttribute(r.attr);
        else r.el.setAttribute(r.attr, r.prevValue);
      }
      restore.length = 0;
      hosts.clear();
      delete G.__SS_SIDEBAR_TREE__;
    },
  };

  G.__SS_SIDEBAR_TREE__ = api;
  if (!A) {
    api.getStatus = () => ({ alive: false, version: VERSION, lastError: 'ADAPTER_MISSING' });
    return;
  }
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }
})();
