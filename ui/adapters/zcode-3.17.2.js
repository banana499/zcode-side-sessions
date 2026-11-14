// ui/adapters/zcode-3.17.2.js
(() => {
  'use strict';
  const G = typeof window !== 'undefined' ? window : globalThis;
  if (G.__SS_ZCODE_ADAPTER__ && G.__SS_ZCODE_ADAPTER__.id === 'zcode-3.17.2' && G.__SS_SIDEBAR_TREE__ && G.__SS_SIDEBAR_TREE__.alive) return;

  const ADAPTER_ID = 'zcode-3.17.2';
  const CONTRACT_ID = 'sidebar-list-v1';
  const SEL = {
    navRoot: '[data-project-sidebar-panel="navigation"]',
    projectTasks: '[data-testid="virtual-project-tasks"]',
    timelineTasks: '[data-testid="project-timeline-tasks"]',
    unreadTasks: '[data-testid="project-unread-tasks"]',
    pinnedTasks: '[data-testid="project-pinned-tasks"]',
    taskContainers:
      '[data-testid="virtual-project-tasks"], [data-testid="project-timeline-tasks"], [data-testid="project-unread-tasks"], [data-testid="project-pinned-tasks"]',
    taskLi: 'li[data-testid^="task-item-"]',
    section: 'section[data-project-id]',
    showMore: '[data-task-list-show-more]',
    titleText: '[data-task-title-copy="original"]',
    conversationFrame: 'section[data-workspace-conversation-frame="true"]',
    chatView: '[data-testid="chat-view"]',
    sideFrameExclude: '[data-workspace-side-frame], [data-testid="subagent-directory"]',
  };
  const TASK_PREFIX = 'task-item-';
  const MAX_WALK = 160;
  const MAX_FRAME_WALK = 160;

  function shortHash(str) {
    if (!str) return '';
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(36);
  }

  function hasClassToken(el, token) {
    if (!el) return false;
    if (el.classList && typeof el.classList.contains === 'function') {
      if (el.classList.contains(token)) return true;
    }
    if (typeof el.className === 'string' && el.className) {
      return el.className.split(/\s+/).includes(token);
    }
    return false;
  }

  function inspectObstruction(el) {
    let cur = el;
    for (let i = 0; cur && i < 30; i++, cur = cur.parentElement) {
      const hasAttr = typeof cur.hasAttribute === 'function';
      const getAttr = typeof cur.getAttribute === 'function';
      if (
        cur.inert === true ||
        (hasAttr && cur.hasAttribute('inert') && (!getAttr || cur.getAttribute('inert') !== 'false')) ||
        (getAttr && cur.getAttribute('data-root-workspace-surface') === 'inert')
      ) {
        return 'inert_workspace';
      }
      if (getAttr && cur.getAttribute('aria-hidden') === 'true') {
        return 'inert_workspace';
      }
      if (
        cur.hidden === true ||
        (hasAttr && cur.hasAttribute('hidden') && (!getAttr || cur.getAttribute('hidden') !== 'false'))
      ) {
        return 'frame_hidden';
      }
      if (hasClassToken(cur, 'opacity-0')) {
        return 'inert_workspace';
      }
      if (cur.style) {
        if (cur.style.display === 'none' || cur.style.visibility === 'hidden') {
          return 'frame_hidden';
        }
        if (cur.style.opacity === '0' || cur.style.opacity === 0) {
          return 'inert_workspace';
        }
      }
      if (typeof getComputedStyle === 'function') {
        try {
          const cs = getComputedStyle(cur);
          if (cs) {
            if (cs.display === 'none' || cs.visibility === 'hidden') return 'frame_hidden';
            if (cs.opacity === '0') return 'inert_workspace';
          }
        } catch (_) {}
      }
    }
    return null;
  }

  function isElementHidden(el) {
    return inspectObstruction(el) !== null;
  }

  const keyOf = (el, prefix) => (el ? Object.keys(el).find(k => k.startsWith(prefix)) : undefined);

  // React 19 的 __reactFiber$ 可能指向旧的那份缓冲：用 __reactProps$ 判断哪一份是当前树。
  function liveFiber(el) {
    if (!el) return null;
    const fk = keyOf(el, '__reactFiber$');
    if (!fk) return null;
    let f = el[fk];
    if (!f) return null;
    const pk = keyOf(el, '__reactProps$');
    const props = pk ? el[pk] : undefined;
    if (
      props !== undefined &&
      f.memoizedProps !== props &&
      f.alternate &&
      f.alternate.memoizedProps === props
    ) {
      f = f.alternate;
    }
    return f;
  }

  // 找 fiber 子树中第一个 HostComponent（tag 5）的 DOM 节点。
  function hostEl(fiber) {
    const stack = [fiber && fiber.child];
    while (stack.length) {
      const f = stack.pop();
      if (!f) continue;
      if (f.tag === 5 && f.stateNode && typeof Element !== 'undefined' && f.stateNode instanceof Element) {
        return f.stateNode;
      }
      stack.push(f.sibling, f.child); // 先 child 后 sibling（后入先出）
    }
    return null;
  }

  function findOCt(liFiber, taskId) {
    let f = liFiber;
    for (let i = 0; f && i < MAX_WALK; i++, f = f.return) {
      const p = f.memoizedProps;
      if (p && p.task && p.task.taskId === taskId && typeof p.onSelect === 'function') return f;
    }
    return null;
  }

  function findTR(octFiber) {
    if (!octFiber || !octFiber.memoizedProps) return null;
    const onSelect = octFiber.memoizedProps.onSelect;
    let f = octFiber.return;
    for (let i = 0; f && i < MAX_WALK; i++, f = f.return) {
      const p = f.memoizedProps;
      if (p && Array.isArray(p.tasks) && p.onSelect === onSelect) return f;
    }
    return null;
  }

  function findWCtTree(trFiber) {
    if (!trFiber) return null;
    let f = trFiber.return;
    for (let i = 0; f && i < MAX_WALK; i++, f = f.return) {
      const p = f.memoizedProps;
      if (p && p.tree && typeof p.tree === 'object') return f;
    }
    return null;
  }

  function resolveSidebarRoot() {
    if (typeof document === 'undefined') return null;
    return document.querySelector(SEL.navRoot);
  }

  // -> [{ row, taskId, wrapper, titleSlot, titleText, task, octFiber, trFiber, wctFiber, hostId, projectId, kind, instanceKey }]
  function findTaskMounts() {
    const root = resolveSidebarRoot();
    if (!root || typeof root.querySelectorAll !== 'function') return [];
    const out = [];
    const rowSel = `${SEL.projectTasks} ${SEL.taskLi}, ${SEL.timelineTasks} ${SEL.taskLi}, ${SEL.unreadTasks} ${SEL.taskLi}, ${SEL.pinnedTasks} ${SEL.taskLi}`;
    for (const li of root.querySelectorAll(rowSel)) {
      if (!li) continue;
      if (li.tagName && String(li.tagName).toUpperCase() !== 'LI') continue;
      if (typeof li.hasAttribute === 'function' && li.hasAttribute('data-grouped-task-key')) continue;
      if (typeof li.closest === 'function') {
        if (li.closest(SEL.sideFrameExclude) || li.closest('[data-grouped-task-key]')) continue;
      }
      const testid = (typeof li.getAttribute === 'function' && li.getAttribute('data-testid')) || '';
      if (!testid.startsWith(TASK_PREFIX)) continue;
      const taskId = testid.slice(TASK_PREFIX.length);
      const lf = liveFiber(li);
      const oct = lf && findOCt(lf, taskId);
      if (!oct) continue;
      const wrapper = hostEl(oct);
      if (!wrapper || !hasClassToken(wrapper, 'py-px') || !wrapper.contains(li)) continue;
      const tr = findTR(oct);
      if (!tr) continue;
      const propKind = tr.memoizedProps && tr.memoizedProps.kind;
      if (
        propKind !== undefined &&
        propKind !== 'project' &&
        propKind !== 'timeline' &&
        propKind !== 'unread' &&
        propKind !== 'pinned'
      ) {
        continue;
      }
      const containerKind =
        typeof li.closest === 'function'
          ? li.closest(SEL.pinnedTasks)
            ? 'pinned'
            : li.closest(SEL.unreadTasks)
              ? 'unread'
              : li.closest(SEL.timelineTasks)
                ? 'timeline'
                : li.closest(SEL.projectTasks)
                  ? 'project'
                  : null
          : null;
      const wct = findWCtTree(tr);
      const section = typeof li.closest === 'function' ? li.closest(SEL.section) : null;
      const titleText = typeof li.querySelector === 'function' ? li.querySelector(SEL.titleText) : null;
      const titleSlot =
        titleText &&
        typeof titleText.closest === 'function' &&
        (titleText.closest('div.flex-1.h-6') ||
          titleText.closest('div.flex.min-w-0.items-center'));
      const taskObj = oct.memoizedProps.task || {};
      const hostId =
        (section && typeof section.getAttribute === 'function' && section.getAttribute('data-project-host')) ||
        taskObj.hostId ||
        'local';
      const projectId =
        (section && typeof section.getAttribute === 'function' && section.getAttribute('data-project-id')) ||
        taskObj.projectId ||
        null;
      const wsDisambig =
        (section &&
          typeof section.getAttribute === 'function' &&
          (section.getAttribute('data-project-workspace-identity') ||
            section.getAttribute('data-workspace-identity') ||
            section.getAttribute('data-workspace-path'))) ||
        taskObj.workspaceIdentity ||
        taskObj.workspacePath ||
        '';
      const wsTag = wsDisambig ? shortHash(String(wsDisambig)) : '';
      const scopeId = wsTag ? `${projectId || '?'}:${wsTag}` : `${projectId || '?'}`;
      const finalKind = propKind || containerKind || (section ? 'project' : 'timeline');
      const instanceKey = `${hostId}:${finalKind}:${scopeId}:${taskId}`;
      out.push({
        row: li,
        taskId,
        wrapper,
        titleSlot,
        titleText,
        task: oct.memoizedProps.task,
        octFiber: oct,
        trFiber: tr,
        wctFiber: wct,
        hostId,
        projectId,
        kind: finalKind,
        instanceKey,
      });
    }
    return out;
  }

  // 活动态：oct.child(div.py-px).child(wCt) 的 props；不会主动推送，由 bundle 轮询。
  function readActive(mount) {
    if (mount && typeof mount.activeTaskId !== 'undefined') {
      return {
        activeTaskId: mount.activeTaskId ?? null,
        isWorkspaceActive: mount.isWorkspaceActive !== false,
      };
    }
    let cur = mount && mount.octFiber && mount.octFiber.child;
    for (let i = 0; cur && i < 6; i++, cur = cur.child) {
      const p = cur.memoizedProps;
      if (p && typeof p === 'object' && ('activeTaskId' in p || 'isWorkspaceActive' in p)) {
        return {
          activeTaskId: p.activeTaskId ?? null,
          isWorkspaceActive: p.isWorkspaceActive !== false,
        };
      }
    }
    return {
      activeTaskId: null,
      isWorkspaceActive: false,
    };
  }

  function queryConversationFrames() {
    if (typeof document === 'undefined') return [];
    let list = [];
    if (typeof document.querySelectorAll === 'function') {
      try {
        list = [...document.querySelectorAll(SEL.conversationFrame)];
      } catch (_) {
        list = [];
      }
    }
    if (!list.length && typeof document.querySelector === 'function') {
      const single = document.querySelector(SEL.conversationFrame);
      if (single) list = [single];
    }
    return list.filter(
      el => !(el && typeof el.closest === 'function' && el.closest(SEL.sideFrameExclude))
    );
  }

  function proveChatViewByFiber(el) {
    let f = liveFiber(el);
    if (!f) return { proven: false, reason: 'no_fiber', workspaceMainView: null, isWorkspaceVisible: undefined };
    let workspaceMainView;
    let isWorkspaceVisible;
    let hasView = false;
    let hasVis = false;
    let matchedFiber = null;
    for (let i = 0; f && i < MAX_FRAME_WALK; i++, f = f.return) {
      const p = f.memoizedProps;
      if (!p || typeof p !== 'object') continue;
      if (!hasView && p.workspaceMainView !== undefined) {
        hasView = true;
        workspaceMainView = p.workspaceMainView;
        if (!matchedFiber) matchedFiber = f;
      }
      if (!hasVis && p.isWorkspaceVisible !== undefined) {
        hasVis = true;
        isWorkspaceVisible = p.isWorkspaceVisible;
        if (!matchedFiber) matchedFiber = f;
      }
      if (hasView && hasVis) break;
    }
    if (!hasView) {
      return {
        proven: false,
        reason: hasVis && isWorkspaceVisible === false ? 'workspace_not_visible' : 'chat_view_unproven',
        workspaceMainView: null,
        isWorkspaceVisible,
      };
    }
    if (workspaceMainView !== 'chat') {
      return { proven: false, reason: 'non_chat_view', workspaceMainView, isWorkspaceVisible };
    }
    if (hasVis && isWorkspaceVisible === false) {
      return { proven: false, reason: 'workspace_not_visible', workspaceMainView, isWorkspaceVisible };
    }
    return { proven: true, reason: null, workspaceMainView, isWorkspaceVisible, fiber: matchedFiber };
  }

  function hasLegacyNonChatView() {
    if (typeof document === 'undefined' || typeof document.querySelector !== 'function') return false;
    const nonChatSel =
      '[data-workspace-view="plugin-store"], [data-workspace-view="automations"], [data-workspace-view="settings"], [data-workspace-panel="plugin-store"], [data-workspace-panel="automations"], [data-testid="plugin-store-view"], [data-testid="automations-view"]';
    let nonChatEl = null;
    try {
      nonChatEl = document.querySelector(nonChatSel);
    } catch (_) {
      nonChatEl = null;
    }
    if (nonChatEl && nonChatEl.isConnected !== false && !isElementHidden(nonChatEl)) {
      const ncRect =
        typeof nonChatEl.getBoundingClientRect === 'function' ? nonChatEl.getBoundingClientRect() : null;
      if (ncRect && ncRect.width > 0 && ncRect.height > 0) {
        return true;
      }
    }
    return false;
  }

  function pickHigherPriorityReason(cur, next) {
    const rank = {
      non_chat_view: 7,
      workspace_not_visible: 6,
      inert_workspace: 5,
      frame_hidden: 4,
      inactive_frame: 3,
      zero_rect: 2,
      chat_view_unproven: 1,
      no_fiber: 1,
      frame_disconnected: 0,
    };
    if (!cur) return next;
    return (rank[next] ?? 0) > (rank[cur] ?? 0) ? next : cur;
  }

  function diagnoseChatViewport() {
    if (typeof document === 'undefined') {
      return { viewport: null, reason: 'no_document' };
    }
    if (hasLegacyNonChatView()) {
      return { viewport: null, reason: 'non_chat_view' };
    }

    const frames = queryConversationFrames();
    if (frames.length > 0) {
      let bestReason = null;
      for (const sec of frames) {
        if (!sec || sec.isConnected === false) {
          bestReason = pickHigherPriorityReason(bestReason, 'frame_disconnected');
          continue;
        }
        const obstruction = inspectObstruction(sec);
        if (obstruction) {
          bestReason = pickHigherPriorityReason(bestReason, obstruction);
          continue;
        }
        if (
          typeof sec.getAttribute === 'function' &&
          (sec.getAttribute('data-active') === 'false' || sec.getAttribute('data-state') === 'inactive')
        ) {
          bestReason = pickHigherPriorityReason(bestReason, 'inactive_frame');
          continue;
        }
        const sectionRect = typeof sec.getBoundingClientRect === 'function' ? sec.getBoundingClientRect() : null;
        if (
          !sectionRect ||
          !(typeof sectionRect.width === 'number' && sectionRect.width > 0) ||
          !(typeof sectionRect.height === 'number' && sectionRect.height > 0)
        ) {
          bestReason = pickHigherPriorityReason(bestReason, 'zero_rect');
          continue;
        }
        const proof = proveChatViewByFiber(sec);
        if (!proof.proven) {
          bestReason = pickHigherPriorityReason(bestReason, proof.reason || 'chat_view_unproven');
          continue;
        }

        let hdr = null;
        if (typeof sec.querySelector === 'function') {
          try {
            hdr = sec.querySelector(':scope > header') || sec.querySelector('header');
          } catch (_) {
            try {
              hdr = sec.querySelector('header');
            } catch (_2) {
              hdr = null;
            }
          }
        }
        let contentTop = sectionRect.top;
        if (hdr && !isElementHidden(hdr) && typeof hdr.getBoundingClientRect === 'function') {
          const headerRect = hdr.getBoundingClientRect();
          if (
            headerRect &&
            typeof headerRect.height === 'number' &&
            headerRect.height > 0 &&
            typeof headerRect.bottom === 'number' &&
            headerRect.bottom >= sectionRect.top &&
            headerRect.bottom < sectionRect.bottom
          ) {
            contentTop = headerRect.bottom;
          }
        }
        return {
          viewport: {
            el: sec,
            headerEl: hdr,
            top: Math.round(contentTop),
            left: Math.round(sectionRect.left),
            width: Math.round(sectionRect.width),
            height: Math.round(sectionRect.height),
            source: 'conversation-frame',
          },
          reason: null,
        };
      }
      return { viewport: null, reason: bestReason || 'chat_view_unproven' };
    }

    const fallbackEl =
      typeof document.querySelector === 'function' ? document.querySelector(SEL.chatView) : null;
    if (!fallbackEl || fallbackEl.isConnected === false) {
      return { viewport: null, reason: 'frame_not_found' };
    }
    const fbObstruction = inspectObstruction(fallbackEl);
    if (fbObstruction) {
      return { viewport: null, reason: fbObstruction };
    }
    if (
      typeof fallbackEl.getAttribute === 'function' &&
      (fallbackEl.getAttribute('data-active') === 'false' || fallbackEl.getAttribute('data-state') === 'inactive')
    ) {
      return { viewport: null, reason: 'inactive_frame' };
    }
    const fbRect =
      typeof fallbackEl.getBoundingClientRect === 'function' ? fallbackEl.getBoundingClientRect() : null;
    if (
      !fbRect ||
      !(typeof fbRect.width === 'number' && fbRect.width > 0) ||
      (typeof fbRect.height === 'number' && fbRect.height <= 0)
    ) {
      return { viewport: null, reason: 'zero_rect' };
    }
    if (liveFiber(fallbackEl)) {
      const fbProof = proveChatViewByFiber(fallbackEl);
      if (!fbProof.proven) {
        return { viewport: null, reason: fbProof.reason || 'chat_view_unproven' };
      }
    }
    return {
      viewport: {
        el: fallbackEl,
        headerEl: null,
        top: Math.round(fbRect.top || 0),
        left: Math.round(fbRect.left || 0),
        width: Math.round(fbRect.width),
        height: typeof fbRect.height === 'number' ? Math.round(fbRect.height) : 600,
        source: 'chat-view',
      },
      reason: null,
    };
  }

  // 解析真实 ZCode 3.18.2 对话内容区视口（正向证明 workspaceMainView==='chat' 且非 inert/隐藏，非聊天页返回 null；保留 [data-testid="chat-view"] 单测桩后备）
  function resolveChatViewport() {
    return diagnoseChatViewport().viewport;
  }

  function readActiveConversationId(mounts) {
    const vp = resolveChatViewport();
    if (!vp) return null;
    if (vp.el) {
      let f = liveFiber(vp.el);
      for (let i = 0; f && i < MAX_FRAME_WALK; i++, f = f.return) {
        const p = f.memoizedProps;
        if (!p || typeof p !== 'object') continue;
        for (const k of ['activeTaskId', 'taskId', 'sessionId', 'conversationId']) {
          if (typeof p[k] === 'string' && p[k]) return p[k];
        }
        if (p.task && typeof p.task === 'object' && typeof p.task.taskId === 'string' && p.task.taskId) {
          return p.task.taskId;
        }
        if (p.session && typeof p.session === 'object' && typeof p.session.id === 'string' && p.session.id) {
          return p.session.id;
        }
      }
    }
    const list = mounts || findTaskMounts();
    for (const m of list) {
      if (m.hostId && m.hostId !== 'local') continue;
      const st = readActive(m);
      if (st.isWorkspaceActive !== false && st.activeTaskId) {
        return st.activeTaskId;
      }
    }
    return null;
  }

  const isNavigable = nt => !!nt && !nt.archived && (nt.hostId || 'local') === 'local';

  // 在所有已挂载 tR 的完整 tasks（不受 slice 限制）里找子会话的原生 task 对象（OCt -> tR -> WCt）。
  function resolveNativeTask(sessionId, mounts) {
    const list = mounts || findTaskMounts();
    const seen = new Set();
    for (const m of list) {
      if (seen.has(m.trFiber)) continue;
      seen.add(m.trFiber);
      if (m.hostId && m.hostId !== 'local') continue;
      const onSelect = m.trFiber.memoizedProps.onSelect;
      if (typeof onSelect !== 'function' || onSelect !== m.octFiber.memoizedProps.onSelect) continue;
      const nt = m.trFiber.memoizedProps.tasks.find(t => t && t.taskId === sessionId);
      if (nt) {
        return {
          nt,
          onSelect,
          trFiber: m.trFiber,
          wctFiber: m.wctFiber || findWCtTree(m.trFiber),
          hostId: m.hostId || nt.hostId || 'local',
        };
      }
    }
    return null;
  }

  // 定位 OCt -> tR -> WCt 五参数选择回调 (workspacePath, taskId, workspaceIdentity, remoteSessionId, unreadAt)，限定 hostId === 'local'
  function resolveNativeNavigator(sessionId, mounts) {
    const list = mounts || findTaskMounts();
    if (sessionId !== undefined && sessionId !== null) {
      const hit = resolveNativeTask(sessionId, list);
      if (!hit) return { ok: false, code: 'NOT_IN_NATIVE_LIST' };
      if (!isNavigable(hit.nt) || hit.hostId !== 'local') return { ok: false, code: 'NOT_NAVIGABLE' };
      const nt = hit.nt;
      return {
        ok: true,
        nt,
        task: nt,
        onSelect: hit.onSelect,
        trFiber: hit.trFiber,
        wctFiber: hit.wctFiber,
        hostId: 'local',
        select: () =>
          hit.onSelect(
            nt.workspacePath,
            nt.taskId,
            nt.workspaceIdentity ?? undefined,
            undefined,
            nt.unreadAt
          ),
      };
    }
    for (const m of list) {
      if (m.hostId !== 'local') continue;
      const onSelect = m.trFiber && m.trFiber.memoizedProps && m.trFiber.memoizedProps.onSelect;
      if (typeof onSelect === 'function' && onSelect === m.octFiber.memoizedProps.onSelect) {
        return {
          ok: true,
          onSelect,
          trFiber: m.trFiber,
          wctFiber: m.wctFiber || findWCtTree(m.trFiber),
          hostId: 'local',
        };
      }
    }
    return { ok: false, code: 'NAVIGATOR_NOT_FOUND' };
  }

  // 从任意已挂载节点向上寻找 ServiceProvider 的 services 对象（含 zcodeSessionService / projectService）
  function resolveHostServices(mounts) {
    const list = mounts || findTaskMounts();
    for (const m of list) {
      let f = m && (m.octFiber || liveFiber(m.row));
      while (f) {
        const p = f.memoizedProps;
        if (p && p.services && p.services.zcodeSessionService) return p.services;
        if (p && p.value && typeof p.value === 'object' && p.value.zcodeSessionService) return p.value;
        f = f.return;
      }
    }
    return null;
  }

  const syncStateBySid = new Map(); // sessionId -> { attempts, nextAt, timerId }
  const titleSyncedSids = new Set();
  let latestNodesBySid = new Map();
  let latestSnap = null;

  function clearSyncTimers() {
    for (const st of syncStateBySid.values()) {
      if (st && st.timerId) {
        clearTimeout(st.timerId);
        st.timerId = 0;
      }
    }
    syncStateBySid.clear();
  }

  async function refreshMountedLists(mounts) {
    for (const m of mounts || []) {
      if (m.octFiber && typeof m.octFiber.memoizedProps?.refresh === 'function') {
        try {
          await m.octFiber.memoizedProps.refresh();
        } catch (_) {}
        break;
      }
    }
  }

  async function syncUnindexedNodes(snap) {
    if (!snap || !Array.isArray(snap.nodes)) return { synced: 0 };
    latestSnap = snap;
    latestNodesBySid = new Map();
    for (const n of snap.nodes) {
      if (!n) continue;
      if (n.sessionId) latestNodesBySid.set(n.sessionId, n);
      if (n.runtimeSessionId) latestNodesBySid.set(n.runtimeSessionId, n);
    }
    const mounts = findTaskMounts();
    const services = resolveHostServices(mounts);
    if (!services || !services.zcodeSessionService) return { synced: 0, reason: 'no_services' };
    let synced = 0;
    const nowMs = Date.now();

    for (const n of snap.nodes) {
      if (!n || !n.parentNodeId || !n.sessionId) continue;
      const hit = resolveNativeTask(n.sessionId, mounts);
      if (hit && hit.nt) {
        const prevSt = syncStateBySid.get(n.sessionId);
        if (prevSt && prevSt.timerId) {
          clearTimeout(prevSt.timerId);
          prevSt.timerId = 0;
        }
        syncStateBySid.delete(n.sessionId);
        const rawNativeTitle = String(hit.nt.title || '').trim();
        if (
          n.title &&
          (!rawNativeTitle ||
            rawNativeTitle.startsWith('<cross-session-message') ||
            rawNativeTitle.startsWith('[side-sessions]')) &&
          !titleSyncedSids.has(n.sessionId) &&
          services.zcodeTaskService &&
          typeof services.zcodeTaskService.renameTask === 'function'
        ) {
          titleSyncedSids.add(n.sessionId);
          try {
            await services.zcodeTaskService.renameTask({
              workspacePath: hit.nt.workspacePath || n.workspacePath,
              taskId: n.sessionId,
              title: n.title,
            });
          } catch (_) {}
        }
        continue;
      }

      if (n.indexState === 'indexed') {
        const prevSt = syncStateBySid.get(n.sessionId);
        if (prevSt && prevSt.timerId) {
          clearTimeout(prevSt.timerId);
          prevSt.timerId = 0;
        }
        syncStateBySid.delete(n.sessionId);
        continue;
      }

      if (n.indexState !== 'pending' || n.canResumeForIndex !== true) continue;
      const wsPath = n.workspacePath || n.parentWorkspacePath || null;
      if (!wsPath) continue;

      let st = syncStateBySid.get(n.sessionId);
      if (!st) {
        st = { attempts: 0, nextAt: 0, timerId: 0 };
        syncStateBySid.set(n.sessionId, st);
      }
      if (st.attempts >= 5 || nowMs < st.nextAt) continue;

      const delayMs = 2000 * Math.pow(2, st.attempts);
      st.attempts += 1;
      st.nextAt = nowMs + delayMs;
      try {
        await services.zcodeSessionService.resumeSession({
          workspacePath: wsPath,
          sessionId: n.sessionId,
          broadcastSnapshot: true,
        });
        synced++;
      } catch (_) {}

      if (st.attempts < 5 && !st.timerId && typeof setTimeout === 'function') {
        st.timerId = setTimeout(() => {
          st.timerId = 0;
          syncUnindexedNodes(latestSnap).catch(() => {});
        }, delayMs);
      }
    }
    if (synced > 0) {
      await refreshMountedLists(mounts);
    }
    return { synced };
  }

  let intentSeq = 0;
  async function navigate(sessionId, fallbackWorkspacePath, nodeMeta) {
    const intent = ++intentSeq;
    const superseded = () => ({ ok: false, code: 'SUPERSEDED', reason: 'SUPERSEDED' });
    let mounts = findTaskMounts();
    let hit = resolveNativeTask(sessionId, mounts);
    if (!hit) {
      const meta = nodeMeta || latestNodesBySid.get(sessionId) || null;
      if (meta && meta.canResumeForIndex === false) {
        return {
          ok: false,
          code: 'TARGET_INDEX_PENDING_ACTIVE_RUN',
          reason: 'TARGET_INDEX_PENDING_ACTIVE_RUN',
        };
      }
      const services = resolveHostServices(mounts);
      const primaryWs = (meta && meta.workspacePath) || fallbackWorkspacePath || null;
      const parentWs = (meta && meta.parentWorkspacePath) || null;
      if (services && services.zcodeSessionService && primaryWs) {
        try {
          await services.zcodeSessionService.resumeSession({
            workspacePath: primaryWs,
            sessionId,
            broadcastSnapshot: true,
          });
          if (intent !== intentSeq) return superseded();
          await refreshMountedLists(mounts);
          if (intent !== intentSeq) return superseded();
          for (let retry = 0; retry < 12 && !hit; retry++) {
            if (intent !== intentSeq) return superseded();
            await new Promise(r => setTimeout(r, 120));
            if (intent !== intentSeq) return superseded();
            mounts = findTaskMounts();
            hit = resolveNativeTask(sessionId, mounts);
          }
          if (!hit && parentWs && parentWs !== primaryWs) {
            await services.zcodeSessionService.resumeSession({
              workspacePath: parentWs,
              sessionId,
              broadcastSnapshot: true,
            });
            if (intent !== intentSeq) return superseded();
            await refreshMountedLists(mounts);
            for (let retry = 0; retry < 6 && !hit; retry++) {
              if (intent !== intentSeq) return superseded();
              await new Promise(r => setTimeout(r, 120));
              if (intent !== intentSeq) return superseded();
              mounts = findTaskMounts();
              hit = resolveNativeTask(sessionId, mounts);
            }
          }
        } catch (_) {
          if (intent !== intentSeq) return superseded();
        }
      }
      if (!hit) {
        return { ok: false, code: 'TARGET_NOT_MOUNTED', reason: 'TARGET_NOT_MOUNTED' };
      }
    }
    if (intent !== intentSeq) return superseded();
    if (!isNavigable(hit.nt) || hit.hostId !== 'local') {
      return { ok: false, code: 'NOT_NAVIGABLE', reason: 'NOT_NAVIGABLE' };
    }
    const nt = hit.nt;
    if (intent !== intentSeq) return superseded();
    await Promise.resolve(
      hit.onSelect(
        nt.workspacePath,
        nt.taskId,
        nt.workspaceIdentity ?? undefined,
        undefined,
        nt.unreadAt
      )
    );
    if (intent !== intentSeq) return superseded();
    // resolve 不是完成凭据：等原生 activeTaskId 真正变成目标
    const nowFn = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
    const t0 = nowFn();
    while (nowFn() - t0 < 5000) {
      if (intent !== intentSeq) return superseded();
      const curMounts = findTaskMounts();
      const matched =
        curMounts.some(x => {
          const act = readActive(x);
          if (act.isWorkspaceActive === false || act.activeTaskId !== nt.taskId) return false;
          if (nt.workspacePath && x.task && x.task.workspacePath) {
            return x.task.workspacePath === nt.workspacePath;
          }
          return true;
        }) || readActiveConversationId(curMounts) === nt.taskId;
      if (matched) return { ok: true, taskId: nt.taskId };
      await new Promise(r => setTimeout(r, 100));
      if (intent !== intentSeq) return superseded();
    }
    return { ok: false, code: 'NATIVE_SWITCH_TIMEOUT', reason: 'NATIVE_SWITCH_TIMEOUT' };
  }

  // ---------- §1.5 子会话顶层去重 + 突破“前 5 条”（suppressDuplicates） ----------
  // p: 原生排序后的 taskId 列表；rootOf: Map(子 taskId -> 在 p 中的最顶层祖先 taskId)；target: 逻辑可见数
  function effectiveLimit(p, rootOf, target) {
    const idx = new Map(p.map((id, i) => [id, i]));
    let L = Math.min(target, p.length);
    for (;;) {
      let shown = 0;
      for (let i = 0; i < L; i++) {
        const r = rootOf.get(p[i]);
        const suppressed = r !== undefined && idx.has(r) && idx.get(r) < L;
        if (!suppressed) shown++;
      }
      if (shown >= Math.min(target, p.length) || L >= p.length) {
        // 剩余的全是被吸收的子行：直接展开到底，避免出现空的“更多”
        let restVisible = 0;
        for (let i = L; i < p.length; i++) {
          const r = rootOf.get(p[i]);
          if (!(r !== undefined && idx.has(r))) restVisible++;
        }
        return restVisible === 0 ? p.length : L;
      }
      L++;
    }
  }

  const dedup = new Map(); // queue(在两份缓冲间共享) -> { target, step, hist:[], disabled, reason, trHost, rafId, usingRaf }
  const showMoreListeners = new Map(); // trHost -> click listener

  function cancelDedupFrame(st) {
    if (!st || !st.rafId) return;
    if (st.usingRaf && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(st.rafId);
    } else {
      clearTimeout(st.rafId);
    }
    st.rafId = 0;
  }

  function hookTriple(f) {
    const tasks = f && f.memoizedProps && f.memoizedProps.tasks;
    if (!Array.isArray(tasks)) return null;
    for (let cur = f && f.memoizedState, steps = 0; cur && steps < 12; cur = cur.next, steps++) {
      const h0 = cur;
      const h1 = h0 && h0.next;
      const h2 = h1 && h1.next;
      if (!h0 || !h1 || !h2) break;
      if (typeof h0.memoizedState !== 'number' || !h0.queue || typeof h0.queue.dispatch !== 'function') continue;
      if (typeof h1.memoizedState !== 'boolean') continue;
      const sorted = h2.memoizedState && h2.memoizedState[0];
      if (!Array.isArray(sorted) || sorted.length !== tasks.length) continue;
      return { h0, h1, sorted };
    }
    return null;
  }

  function countOCt(trF) {
    const onSelect = trF.memoizedProps.onSelect;
    let n = 0;
    const stack = [trF.child];
    while (stack.length) {
      const f = stack.pop();
      if (!f) continue;
      const p = f.memoizedProps;
      if (p && p.task && p.onSelect === onSelect) {
        n++;
        stack.push(f.sibling);
        continue;
      }
      stack.push(f.sibling, f.child);
    }
    return n;
  }

  function pickTR(trF) {
    for (const f of [trF, trF && trF.alternate]) {
      const t = f && hookTriple(f);
      if (t && countOCt(f) === Math.min(t.h0.memoizedState, t.sorted.length)) return { f, ...t };
    }
    return null;
  }

  function isNodeRenderable(n) {
    return Boolean(
      n && !n.archived && n.nodeStatus !== 'archived' && (n.hostId || 'local') === 'local'
    );
  }

  function buildRootOf(ids, bySid, byNodeId) {
    const inList = new Set(ids);
    const rootOf = new Map();
    if (!bySid || !byNodeId) return rootOf;
    const visited = new Set();
    for (const sid of ids) {
      let n = bySid.get(sid);
      if (!isNodeRenderable(n)) continue;
      let top;
      visited.clear();
      while (n && n.parentNodeId) {
        if (visited.has(n.nodeId)) break;
        visited.add(n.nodeId);
        const parent = byNodeId.get(n.parentNodeId);
        if (!isNodeRenderable(parent)) break;
        const parentSid = parent.runtimeSessionId || parent.sessionId;
        if (parentSid && inList.has(parentSid)) top = parentSid;
        n = parent;
      }
      if (top) rootOf.set(sid, top);
    }
    return rootOf;
  }

  function unsuppress(mounts) {
    for (const m of mounts || []) {
      if (m && m.wrapper) m.wrapper.removeAttribute('data-ss-suppressed');
    }
  }

  function suppressDuplicates(mountsOfTR, bySid, byNodeId) {
    if (
      !mountsOfTR ||
      !mountsOfTR.length ||
      mountsOfTR[0].kind === 'pinned' ||
      mountsOfTR[0].trFiber?.memoizedProps?.kind === 'pinned'
    ) {
      return { state: 'skipped:pinned' };
    }
    const trF0 = mountsOfTR[0].trFiber;
    const trHost = hostEl(trF0);
    if (
      !trHost ||
      typeof trHost.closest !== 'function' ||
      trHost.closest(SEL.sideFrameExclude) ||
      (!trHost.closest(SEL.projectTasks) &&
        !trHost.closest(SEL.timelineTasks) &&
        !trHost.closest(SEL.unreadTasks))
    ) {
      return { state: 'skipped:not_project' };
    }
    const picked = pickTR(trF0);
    if (!picked) {
      unsuppress(mountsOfTR);
      return { state: 'disabled:hook_shape' };
    }
    const { f: tR, h0, sorted } = picked;
    const q = h0.queue;
    const listKind = (tR.memoizedProps && tR.memoizedProps.kind) || mountsOfTR[0].kind;
    const step = listKind === 'timeline' || listKind === 'unread' ? 20 : 5;
    let st = dedup.get(q);
    if (!st) {
      st = { target: h0.memoizedState, step, hist: [], disabled: false, trHost, rafId: 0, usingRaf: false };
      dedup.set(q, st);
    } else {
      st.step = step;
      st.trHost = trHost;
    }
    if (st.disabled) {
      unsuppress(mountsOfTR);
      return { state: st.reason || 'disabled:breaker' };
    }

    if (!showMoreListeners.has(trHost)) {
      const onClick = e => {
        if (
          !st.disabled &&
          dedup.get(q) === st &&
          typeof Element !== 'undefined' &&
          e.target instanceof Element &&
          e.target.closest(SEL.showMore)
        ) {
          st.target += st.step;
        }
      };
      trHost.addEventListener('click', onClick, true);
      showMoreListeners.set(trHost, onClick);
    }

    const ids = sorted.map(t => t.taskId);
    const rootOf = buildRootOf(ids, bySid, byNodeId);
    const L = effectiveLimit(ids, rootOf, st.target);
    if (L !== h0.memoizedState) {
      const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
      st.hist = st.hist.filter(t => now - t < 1000);
      if (st.hist.length >= 5) {
        cancelDedupFrame(st);
        st.disabled = true;
        st.reason = 'disabled:breaker';
        q.dispatch(st.target);
        unsuppress(mountsOfTR);
        return { state: st.reason };
      }
      st.hist.push(now);
      cancelDedupFrame(st);
      const useRaf = typeof requestAnimationFrame === 'function';
      st.usingRaf = useRaf;
      const scheduleFrame = useRaf ? requestAnimationFrame : fn => setTimeout(fn, 0);
      st.rafId = scheduleFrame(() => {
        st.rafId = 0;
        if (st.disabled || dedup.get(q) !== st) return;
        q.dispatch(L);
      });
    }
    const idx = new Map(ids.map((id, i) => [id, i]));
    const hiddenChildIds = [...rootOf.keys()];
    for (const m of mountsOfTR) {
      const r = rootOf.get(m.taskId);
      const hide = (m.hostId || 'local') === 'local' && r !== undefined && idx.get(r) < L;
      if (hide) m.wrapper.setAttribute('data-ss-suppressed', '1');
      else m.wrapper.removeAttribute('data-ss-suppressed');
    }
    return { state: 'active', L, target: st.target, hidden: hiddenChildIds.length, hiddenChildIds };
  }

  function restoreDedup(opts) {
    const shouldDispatch = !opts || opts.dispatch !== false;
    const mounts = opts && opts.mounts;
    intentSeq++;
    clearSyncTimers();
    for (const [trHost, onClick] of showMoreListeners) {
      try {
        trHost.removeEventListener('click', onClick, true);
      } catch (_) {}
    }
    showMoreListeners.clear();
    for (const [q, st] of dedup) {
      cancelDedupFrame(st);
      const wasDisabled = st.disabled;
      st.disabled = true;
      if (!st.reason) st.reason = 'disabled:restored';
      if (shouldDispatch && !wasDisabled) {
        try {
          q.dispatch(st.target);
        } catch (_) {}
      }
    }
    if (shouldDispatch) {
      dedup.clear();
    }
    if (mounts) {
      unsuppress(mounts);
    }
    if (typeof document !== 'undefined' && typeof document.querySelectorAll === 'function') {
      document.querySelectorAll('[data-ss-suppressed]').forEach(el => el.removeAttribute('data-ss-suppressed'));
    }
  }

  function diagnoseRawRowMismatch(root) {
    if (!root || typeof root.querySelectorAll !== 'function') return [];
    const filterEligible = el =>
      el &&
      (!el.tagName || String(el.tagName).toUpperCase() === 'LI') &&
      !(typeof el.hasAttribute === 'function' && el.hasAttribute('data-grouped-task-key')) &&
      !(
        typeof el.closest === 'function' &&
        (el.closest(SEL.sideFrameExclude) || el.closest('[data-grouped-task-key]'))
      );

    const rowSel = `${SEL.projectTasks} ${SEL.taskLi}, ${SEL.timelineTasks} ${SEL.taskLi}, ${SEL.unreadTasks} ${SEL.taskLi}, ${SEL.pinnedTasks} ${SEL.taskLi}`;
    const insideContainers = [...root.querySelectorAll(rowSel)].filter(filterEligible);
    if (insideContainers.length === 0) {
      const anyTaskLis = [...root.querySelectorAll(SEL.taskLi)].filter(filterEligible);
      if (anyTaskLis.length > 0) return ['container_selector_mismatch'];
      return [];
    }

    const reasons = new Set();
    for (const li of insideContainers) {
      const testid = (typeof li.getAttribute === 'function' && li.getAttribute('data-testid')) || '';
      if (!testid.startsWith(TASK_PREFIX)) continue;
      const taskId = testid.slice(TASK_PREFIX.length);
      const lf = liveFiber(li);
      if (!lf) {
        reasons.add('fiber_missing');
        continue;
      }
      const oct = findOCt(lf, taskId);
      if (!oct) {
        reasons.add('oct_contract_mismatch');
        continue;
      }
      const wrapper = hostEl(oct);
      if (!wrapper || !hasClassToken(wrapper, 'py-px') || !wrapper.contains(li)) {
        reasons.add('wrapper_contract_mismatch');
        continue;
      }
      const tr = findTR(oct);
      if (!tr) {
        reasons.add('tr_contract_mismatch');
        continue;
      }
      const pk = tr.memoizedProps && tr.memoizedProps.kind;
      if (pk !== undefined && pk !== 'project' && pk !== 'timeline' && pk !== 'unread' && pk !== 'pinned') {
        reasons.add('tr_kind_unsupported');
      }
    }
    return [...reasons];
  }

  function selfTest() {
    const root = resolveSidebarRoot();
    const vpDiag = diagnoseChatViewport();
    const chatViewportOk = Boolean(vpDiag.viewport);

    if (!root) {
      let structuralMismatch = false;
      let reason = 'sidebar_not_mounted';
      if (typeof document !== 'undefined' && typeof document.querySelector === 'function') {
        try {
          const otherSidebar = document.querySelector('[data-project-sidebar-panel]');
          if (otherSidebar) {
            structuralMismatch = true;
            reason = 'sidebar_selector_mismatch';
          }
        } catch (_) {}
      }
      return {
        contractId: CONTRACT_ID,
        state: structuralMismatch ? 'unsupported' : 'waiting',
        capabilities: {
          mount: false,
          navigation: false,
          chatViewport: chatViewportOk,
          hostIndexSync: false,
          dedup: false,
        },
        diagnostics: {
          sidebarFound: false,
          reason,
          mountCount: 0,
          localMountCount: 0,
          views: [],
          groupedOrdinaryDegraded: false,
          chatViewportReason: vpDiag.reason,
          dedupReason: null,
          unsupportedReasons: structuralMismatch ? [reason] : [],
          waitingReasons: structuralMismatch ? [] : [reason],
        },
      };
    }

    const mounts = findTaskMounts();
    const localMounts = mounts.filter(m => m.hostId === 'local');
    let groupedDivs = [];
    if (typeof root.querySelectorAll === 'function') {
      try {
        groupedDivs = [...root.querySelectorAll('div[data-grouped-task-key], [role="button"][data-grouped-task-key]')].filter(
          el => !(typeof el.closest === 'function' && el.closest(SEL.sideFrameExclude))
        );
      } catch (_) {
        groupedDivs = [];
      }
    }
    const groupedOrdinaryDegraded = groupedDivs.length > 0;
    const views = [...new Set(mounts.map(m => m.kind))];

    if (mounts.length === 0) {
      const mismatchReasons = diagnoseRawRowMismatch(root);
      if (mismatchReasons.length > 0) {
        return {
          contractId: CONTRACT_ID,
          state: 'unsupported',
          capabilities: {
            mount: false,
            navigation: false,
            chatViewport: chatViewportOk,
            hostIndexSync: false,
            dedup: false,
          },
          diagnostics: {
            sidebarFound: true,
            reason: mismatchReasons[0],
            mountCount: 0,
            localMountCount: 0,
            views: [],
            groupedOrdinaryDegraded,
            chatViewportReason: vpDiag.reason,
            dedupReason: null,
            unsupportedReasons: mismatchReasons,
            waitingReasons: [],
          },
        };
      }
      let isLoading = false;
      if (typeof root.querySelector === 'function') {
        try {
          isLoading = Boolean(root.querySelector('[aria-busy="true"], [data-loading="true"]'));
        } catch (_) {}
      }
      const waitingReason = isLoading
        ? 'loading'
        : groupedOrdinaryDegraded
          ? 'grouped_ordinary_degraded'
          : 'empty_task_list';
      return {
        contractId: CONTRACT_ID,
        state: 'waiting',
        capabilities: {
          mount: false,
          navigation: false,
          chatViewport: chatViewportOk,
          hostIndexSync: false,
          dedup: false,
        },
        diagnostics: {
          sidebarFound: true,
          reason: waitingReason,
          mountCount: 0,
          localMountCount: 0,
          views: [],
          groupedOrdinaryDegraded,
          chatViewportReason: vpDiag.reason,
          dedupReason: null,
          unsupportedReasons: [],
          waitingReasons: [waitingReason],
        },
      };
    }

    const navOk = localMounts.some(
      m =>
        m.trFiber &&
        m.trFiber.memoizedProps &&
        typeof m.trFiber.memoizedProps.onSelect === 'function' &&
        m.octFiber &&
        m.octFiber.memoizedProps &&
        m.trFiber.memoizedProps.onSelect === m.octFiber.memoizedProps.onSelect &&
        isNavigable(m.task)
    );

    const services = resolveHostServices(mounts);
    const hostIndexSyncOk = Boolean(
      services &&
        services.zcodeSessionService &&
        typeof services.zcodeSessionService.resumeSession === 'function'
    );

    let dedupOk = true;
    let dedupReason = null;
    for (const st of dedup.values()) {
      if (st && st.disabled) {
        dedupOk = false;
        dedupReason = st.reason || 'disabled:breaker';
        break;
      }
    }
    const seenTR = new Set();
    let nonPinnedTRCount = 0;
    if (dedupOk) {
      for (const m of mounts) {
        if (
          m.kind === 'pinned' ||
          (m.trFiber && m.trFiber.memoizedProps && m.trFiber.memoizedProps.kind === 'pinned')
        ) {
          continue;
        }
        if (!m.trFiber || seenTR.has(m.trFiber)) continue;
        seenTR.add(m.trFiber);
        nonPinnedTRCount++;
        const trHost = hostEl(m.trFiber);
        const inDedupContainer =
          trHost &&
          typeof trHost.closest === 'function' &&
          !trHost.closest(SEL.sideFrameExclude) &&
          (trHost.closest(SEL.projectTasks) ||
            trHost.closest(SEL.timelineTasks) ||
            trHost.closest(SEL.unreadTasks));
        if (!inDedupContainer || !pickTR(m.trFiber)) {
          dedupOk = false;
          dedupReason = 'disabled:hook_shape';
          break;
        }
      }
    }
    if (!dedupOk) {
      restoreDedup({ dispatch: false, mounts });
    } else if (nonPinnedTRCount === 0 && groupedOrdinaryDegraded) {
      dedupOk = false;
      dedupReason = 'grouped_ordinary_degraded';
    }

    return {
      contractId: CONTRACT_ID,
      state: 'ready',
      capabilities: {
        mount: true,
        navigation: navOk,
        chatViewport: chatViewportOk,
        hostIndexSync: hostIndexSyncOk,
        dedup: dedupOk,
      },
      diagnostics: {
        sidebarFound: true,
        reason: null,
        mountCount: mounts.length,
        localMountCount: localMounts.length,
        views,
        groupedOrdinaryDegraded,
        chatViewportReason: vpDiag.reason,
        dedupReason,
        unsupportedReasons: [],
        waitingReasons: [],
      },
    };
  }

  function selfCheck() {
    const res = selfTest();
    return {
      sidebarFound: Boolean(res.diagnostics && res.diagnostics.sidebarFound),
      octResolved: Boolean(res.capabilities && res.capabilities.mount),
      navigatorResolved: Boolean(res.capabilities && res.capabilities.navigation),
      contractId: res.contractId,
      state: res.state,
      capabilities: res.capabilities,
      diagnostics: res.diagnostics,
    };
  }

  G.__SS_ZCODE_ADAPTER__ = {
    id: ADAPTER_ID,
    contractId: CONTRACT_ID,
    SEL,
    liveFiber,
    hostEl,
    findOCt,
    findTR,
    findWCtTree,
    resolveSidebarRoot,
    resolveChatViewport,
    findTaskMounts,
    readActive,
    readActiveConversationId,
    resolveNativeTask,
    resolveNativeNavigator,
    resolveHostServices,
    syncUnindexedNodes,
    isNavigable,
    navigate,
    openChild: navigate,
    selfTest,
    selfCheck,
    effectiveLimit,
    buildRootOf,
    suppressDuplicates,
    restoreDedup,
    dedupStatus: () =>
      [...dedup.values()].map(s => ({
        target: s.target,
        disabled: s.disabled,
        reason: s.reason || null,
      })),
  };
})();
