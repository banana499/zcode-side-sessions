import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, '../..');
const ADAPTER_CODE = fs.readFileSync(path.join(PLUGIN_ROOT, 'ui/adapters/zcode-3.17.2.js'), 'utf8');
const BUNDLE_CODE = fs.readFileSync(path.join(PLUGIN_ROOT, 'ui/sidebar_tree_bundle.js'), 'utf8');

class FakeClassList {
  constructor(el) {
    this._el = el;
  }
  _tokens() {
    return (this._el._className || '').split(/\s+/).filter(Boolean);
  }
  contains(tok) {
    return this._tokens().includes(tok);
  }
  add(...toks) {
    const set = new Set(this._tokens());
    for (const t of toks) if (t) set.add(t);
    this._el._className = [...set].join(' ');
  }
  remove(...toks) {
    const rm = new Set(toks);
    this._el._className = this._tokens().filter(t => !rm.has(t)).join(' ');
  }
}

function matchSimpleSelector(el, sel) {
  if (!el || el.nodeType !== 1) return false;
  let rest = sel.trim();
  if (!rest) return false;

  // Tag at start
  const tagMatch = rest.match(/^([a-zA-Z][a-zA-Z0-9-]*)/);
  if (tagMatch) {
    if (el.tagName !== tagMatch[1].toUpperCase()) return false;
    rest = rest.slice(tagMatch[0].length);
  }

  while (rest.length > 0) {
    if (rest[0] === '.') {
      const m = rest.match(/^\.([a-zA-Z0-9_-]+)/);
      if (!m) return false;
      if (!el.classList.contains(m[1])) return false;
      rest = rest.slice(m[0].length);
    } else if (rest[0] === '#') {
      const m = rest.match(/^#([a-zA-Z0-9_-]+)/);
      if (!m) return false;
      if (el.id !== m[1]) return false;
      rest = rest.slice(m[0].length);
    } else if (rest[0] === '[') {
      const end = rest.indexOf(']');
      if (end === -1) return false;
      const inner = rest.slice(1, end).trim();
      rest = rest.slice(end + 1);
      const eqIdx = inner.indexOf('=');
      if (eqIdx === -1) {
        if (!el.hasAttribute(inner)) return false;
      } else {
        let op = '=';
        let attr = inner.slice(0, eqIdx);
        if (attr.endsWith('^')) {
          op = '^=';
          attr = attr.slice(0, -1);
        }
        attr = attr.trim();
        let val = inner.slice(eqIdx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        const actual = el.getAttribute(attr);
        if (actual === null) return false;
        if (op === '=' && actual !== val) return false;
        if (op === '^=' && !actual.startsWith(val)) return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

function matchCompoundChain(el, parts, rootScope) {
  // parts: array of { combinator: ' ' | '>', selector: string } from left to right
  let idx = parts.length - 1;
  const last = parts[idx];
  if (last.selector === ':scope') return el === rootScope;
  if (!matchSimpleSelector(el, last.selector)) return false;
  let cur = el;
  for (idx = parts.length - 2; idx >= 0; idx--) {
    const combinator = parts[idx + 1].combinator;
    const targetSel = parts[idx].selector;
    if (targetSel === ':scope') {
      if (combinator === '>') return cur.parentElement === rootScope;
      let p = cur.parentElement;
      while (p) {
        if (p === rootScope) return true;
        p = p.parentElement;
      }
      return false;
    }
    if (combinator === '>') {
      cur = cur.parentElement;
      if (!cur || !matchSimpleSelector(cur, targetSel)) return false;
    } else {
      let p = cur.parentElement;
      let matched = null;
      while (p) {
        if (matchSimpleSelector(p, targetSel)) {
          matched = p;
          break;
        }
        p = p.parentElement;
      }
      if (!matched) return false;
      cur = matched;
    }
  }
  return true;
}

function parseSelectorParts(singleSel) {
  const tokens = [];
  let i = 0;
  const s = singleSel.trim();
  let cur = '';
  let inBracket = false;
  let pendingComb = ' ';
  while (i < s.length) {
    const ch = s[i];
    if (ch === '[') inBracket = true;
    else if (ch === ']') inBracket = false;
    if (!inBracket && (ch === '>' || ch === ' ' || ch === '\t' || ch === '\n')) {
      if (cur) {
        tokens.push({ combinator: tokens.length === 0 ? null : pendingComb, selector: cur });
        cur = '';
        pendingComb = ' ';
      }
      if (ch === '>') pendingComb = '>';
      i++;
      continue;
    }
    cur += ch;
    i++;
  }
  if (cur) {
    tokens.push({ combinator: tokens.length === 0 ? null : pendingComb, selector: cur });
  }
  return tokens;
}

function splitSelectors(selectorText) {
  const list = [];
  let cur = '';
  let inBracket = false;
  let quote = null;
  for (const ch of selectorText) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '[') inBracket = true;
    else if (ch === ']') inBracket = false;
    if (ch === ',' && !inBracket) {
      if (cur.trim()) list.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) list.push(cur.trim());
  return list;
}

function matchesSelector(el, selectorText, rootScope = null) {
  for (const single of splitSelectors(selectorText)) {
    const parts = parseSelectorParts(single);
    if (parts.length && matchCompoundChain(el, parts, rootScope)) return true;
  }
  return false;
}

class FakeElement {
  constructor(tagName = 'div', rect = { top: 0, bottom: 24, left: 0, right: 200, width: 200, height: 24 }) {
    this.nodeType = 1;
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.parentElement = null;
    this.attrs = new Map();
    this.listeners = new Map();
    this.style = {
      _props: new Map(),
      setProperty: (k, v) => {
        this.style._props.set(k, v);
        this.style[k] = v;
      },
    };
    this._className = '';
    this.classList = new FakeClassList(this);
    this._rect = rect;
    this._textContent = '';
    this.hidden = false;
    this.inert = false;
    this.draggable = false;
    this.disabled = false;
    this.id = '';
  }

  get className() {
    return this._className;
  }
  set className(v) {
    this._className = String(v || '');
  }
  get textContent() {
    if (this.children.length === 0) return this._textContent;
    return this.children.map(c => (c.nodeType === 3 ? c.textContent : c.textContent)).join('');
  }
  set textContent(v) {
    this._textContent = String(v ?? '');
    this.children = [];
  }
  get isConnected() {
    let cur = this;
    while (cur.parentElement) cur = cur.parentElement;
    return cur._isRootDoc === true;
  }
  get lastElementChild() {
    for (let i = this.children.length - 1; i >= 0; i--) {
      if (this.children[i].nodeType === 1) return this.children[i];
    }
    return null;
  }
  setAttribute(k, v) {
    const val = String(v);
    if (k === 'id') this.id = val;
    if (k === 'class') this._className = val;
    if (k === 'hidden') this.hidden = true;
    if (k === 'inert') this.inert = val !== 'false';
    this.attrs.set(k, val);
  }
  getAttribute(k) {
    if (k === 'id' && this.id) return this.id;
    if (k === 'class' && this._className) return this._className;
    if (k === 'hidden' && this.hidden && !this.attrs.has('hidden')) return '';
    if (k === 'inert' && this.inert && !this.attrs.has('inert')) return '';
    return this.attrs.has(k) ? this.attrs.get(k) : null;
  }
  hasAttribute(k) {
    if (k === 'hidden' && this.hidden) return true;
    if (k === 'inert' && this.inert) return true;
    return this.attrs.has(k);
  }
  removeAttribute(k) {
    if (k === 'id') this.id = '';
    if (k === 'hidden') this.hidden = false;
    if (k === 'inert') this.inert = false;
    this.attrs.delete(k);
  }
  append(...nodes) {
    for (const n of nodes) {
      if (!n) continue;
      if (n.parentElement) n.remove();
      if (n.nodeType === 1) n.parentElement = this;
      this.children.push(n);
    }
  }
  appendChild(n) {
    this.append(n);
    return n;
  }
  replaceChildren(...nodes) {
    for (const c of this.children) {
      if (c && c.nodeType === 1) c.parentElement = null;
    }
    this.children = [];
    this.append(...nodes);
  }
  replaceWith(other) {
    if (!this.parentElement || !other) return;
    const idx = this.parentElement.children.indexOf(this);
    if (idx !== -1) {
      if (other.parentElement) other.remove();
      other.parentElement = this.parentElement;
      this.parentElement.children[idx] = other;
      this.parentElement = null;
    }
  }
  remove() {
    if (!this.parentElement) return;
    this.parentElement.children = this.parentElement.children.filter(c => c !== this);
    this.parentElement = null;
  }
  contains(other) {
    if (other === this) return true;
    return this.children.some(c => c.nodeType === 1 && c.contains(other));
  }
  closest(sel) {
    let cur = this;
    while (cur) {
      if (matchesSelector(cur, sel, null)) return cur;
      cur = cur.parentElement;
    }
    return null;
  }
  querySelectorAll(sel) {
    const out = [];
    const walk = node => {
      for (const c of node.children) {
        if (c.nodeType !== 1) continue;
        if (matchesSelector(c, sel, this)) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  addEventListener(ev, fn) {
    if (!this.listeners.has(ev)) this.listeners.set(ev, []);
    this.listeners.get(ev).push(fn);
  }
  removeEventListener(ev, fn) {
    const arr = this.listeners.get(ev);
    if (!arr) return;
    this.listeners.set(
      ev,
      arr.filter(f => f !== fn)
    );
  }
  dispatchEvent(ev) {
    const arr = this.listeners.get(ev.type) || [];
    for (const fn of [...arr]) fn(ev);
  }
  getBoundingClientRect() {
    return this._rect;
  }
  focus() {}
  select() {}
}

function createDomEnv() {
  const html = new FakeElement('html');
  html._isRootDoc = true;
  const head = new FakeElement('head');
  const body = new FakeElement('body');
  html.append(head, body);

  const winListeners = new Map();
  const intervals = new Set();
  const timeouts = new Set();
  let nextTimerId = 1;

  const doc = {
    hidden: false,
    readyState: 'complete',
    activeElement: null,
    head,
    body,
    documentElement: html,
    createElement: tag => new FakeElement(tag),
    createTextNode: txt => ({ nodeType: 3, textContent: String(txt) }),
    getElementById: id => html.querySelector(`#${id}`),
    querySelector: sel => html.querySelector(sel),
    querySelectorAll: sel => html.querySelectorAll(sel),
    addEventListener: () => {},
    removeEventListener: () => {},
    execCommand: () => false,
  };

  const sandbox = {
    console,
    Map,
    Set,
    Array,
    Object,
    String,
    Number,
    Boolean,
    Math,
    Date,
    Promise,
    Error,
    RegExp,
    JSON,
    Element: FakeElement,
    document: doc,
    localStorage: {
      _m: new Map(),
      getItem(k) {
        return this._m.has(k) ? this._m.get(k) : null;
      },
      setItem(k, v) {
        this._m.set(k, String(v));
      },
      removeItem(k) {
        this._m.delete(k);
      },
    },
    MutationObserver: class {
      constructor(cb) {
        this.cb = cb;
      }
      observe() {}
      disconnect() {}
    },
    ResizeObserver: class {
      constructor(cb) {
        this.cb = cb;
      }
      observe() {}
      disconnect() {}
    },
    requestAnimationFrame: fn => {
      const id = nextTimerId++;
      timeouts.add(id);
      fn();
      timeouts.delete(id);
      return id;
    },
    cancelAnimationFrame: id => timeouts.delete(id),
    setTimeout: (fn, ms) => {
      const id = nextTimerId++;
      timeouts.add(id);
      return id;
    },
    clearTimeout: id => timeouts.delete(id),
    setInterval: () => {
      const id = nextTimerId++;
      intervals.add(id);
      return id;
    },
    clearInterval: id => intervals.delete(id),
    queueMicrotask,
    addEventListener: (ev, fn) => {
      if (!winListeners.has(ev)) winListeners.set(ev, []);
      winListeners.get(ev).push(fn);
    },
    removeEventListener: (ev, fn) => {
      const arr = winListeners.get(ev);
      if (arr) winListeners.set(ev, arr.filter(f => f !== fn));
    },
    getComputedStyle: el => ({
      display: el.style.display || 'block',
      visibility: el.style.visibility || 'visible',
      opacity: el.style.opacity !== undefined ? String(el.style.opacity) : '1',
    }),
    crypto: globalThis.crypto,
    performance: globalThis.performance,
    _intervals: intervals,
    _timeouts: timeouts,
    _winListeners: winListeners,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  return { sandbox, doc, html, head, body };
}

function loadAdapter(sandbox) {
  vm.runInContext(ADAPTER_CODE, sandbox);
  return sandbox.__SS_ZCODE_ADAPTER__;
}

function loadBundle(sandbox) {
  vm.runInContext(BUNDLE_CODE, sandbox);
  return sandbox.__SS_SIDEBAR_TREE__;
}

const FIBER_KEY = '__reactFiber$test19';
const PROPS_KEY = '__reactProps$test19';

function buildTaskListFixture({
  containerTestId,
  kind,
  tasks,
  limit = 5,
  activeTaskId = null,
  isWorkspaceActive = true,
  sectionAttrs = null,
  services = null,
  onSelect = null,
  useAlternate = false,
  brokenWrapper = false,
  brokenOCt = false,
  brokenTR = false,
  brokenHookShape = false,
  dispatchSpy = null,
}) {
  const selectFn = onSelect || (() => {});
  const hostDiv = new FakeElement('div');
  hostDiv.setAttribute('data-testid', containerTestId);
  const ul = new FakeElement('ul');
  hostDiv.append(ul);

  const h2 = { memoizedState: [tasks, []], next: null };
  const h1 = { memoizedState: brokenHookShape ? 'not-a-boolean' : false, next: h2 };
  const h0Queue = {
    dispatch(nextL) {
      if (dispatchSpy) dispatchSpy(nextL);
      const val = typeof nextL === 'function' ? nextL(h0.memoizedState) : nextL;
      h0.memoizedState = val;
    },
  };
  const h0 = { memoizedState: limit, queue: h0Queue, next: h1 };

  const providerFiber = services
    ? { tag: 0, memoizedProps: { services }, return: null }
    : null;
  const wctTreeFiber = {
    tag: 0,
    memoizedProps: { tree: { projects: ['p1'] } },
    return: providerFiber,
  };
  const trFiber = {
    tag: 0,
    memoizedProps: brokenTR ? { tasks } : { tasks, onSelect: selectFn, kind },
    memoizedState: h0,
    return: wctTreeFiber,
    child: null,
    sibling: null,
    alternate: null,
  };
  const trHostFiber = {
    tag: 5,
    stateNode: hostDiv,
    memoizedProps: {},
    return: trFiber,
    child: null,
    sibling: null,
  };
  trFiber.child = trHostFiber;

  const visible = tasks.slice(0, limit);
  const wrappers = [];
  let prevOct = null;
  for (const t of visible) {
    const wrapper = new FakeElement('div');
    if (!brokenWrapper) wrapper.className = 'py-px';
    const li = new FakeElement('li');
    li.setAttribute('data-testid', `task-item-${t.taskId}`);
    const slot = new FakeElement('div');
    slot.className = 'flex-1 h-6';
    const titleSpan = new FakeElement('span');
    titleSpan.setAttribute('data-task-title-copy', 'original');
    titleSpan.textContent = t.title || t.taskId;
    slot.append(titleSpan);
    li.append(slot);
    wrapper.append(li);
    ul.append(wrapper);
    wrappers.push({ wrapper, li, slot, titleSpan });

    const wctItemFiber = {
      tag: 0,
      memoizedProps: { activeTaskId, isWorkspaceActive },
      return: null,
      child: null,
      sibling: null,
    };
    const wrapperFiber = {
      tag: 5,
      stateNode: wrapper,
      memoizedProps: { className: wrapper.className },
      return: null,
      child: wctItemFiber,
      sibling: null,
    };
    wctItemFiber.return = wrapperFiber;
    const octFiber = {
      tag: 0,
      memoizedProps: brokenOCt ? { task: { taskId: 'wrong' } } : { task: t, onSelect: selectFn },
      return: trFiber,
      child: wrapperFiber,
      sibling: null,
    };
    wrapperFiber.return = octFiber;

    const currentLiProps = { 'data-testid': `task-item-${t.taskId}` };
    const liveLiFiber = {
      tag: 5,
      stateNode: li,
      memoizedProps: currentLiProps,
      return: wctItemFiber,
      child: null,
      sibling: null,
    };
    if (useAlternate) {
      const staleLiFiber = {
        tag: 5,
        stateNode: li,
        memoizedProps: { 'data-testid': 'stale-row' },
        return: null,
        alternate: liveLiFiber,
      };
      liveLiFiber.alternate = staleLiFiber;
      li[FIBER_KEY] = staleLiFiber;
    } else {
      li[FIBER_KEY] = liveLiFiber;
    }
    li[PROPS_KEY] = currentLiProps;

    if (!trHostFiber.child) trHostFiber.child = octFiber;
    else prevOct.sibling = octFiber;
    prevOct = octFiber;
  }

  let mountRoot = hostDiv;
  if (sectionAttrs) {
    const sec = new FakeElement('section');
    for (const [k, v] of Object.entries(sectionAttrs)) {
      sec.setAttribute(k, v);
    }
    sec.append(hostDiv);
    mountRoot = sec;
  }

  return { mountRoot, hostDiv, ul, trFiber, h0, h0Queue, wrappers };
}

function attachChatFrame(body, {
  workspaceMainView = 'chat',
  isWorkspaceVisible = true,
  activeTaskId = null,
  inert = false,
  ariaHidden = false,
  opacity0 = false,
  noFiber = false,
  rect = { top: 0, bottom: 720, left: 260, right: 1160, width: 900, height: 720 },
  headerHeight = 48,
} = {}) {
  const surface = new FakeElement('div');
  if (inert) {
    surface.setAttribute('data-root-workspace-surface', 'inert');
    surface.setAttribute('inert', '');
  }
  if (ariaHidden) surface.setAttribute('aria-hidden', 'true');
  if (opacity0) surface.classList.add('opacity-0');

  const sec = new FakeElement('section', rect);
  sec.setAttribute('data-workspace-conversation-frame', 'true');
  const hdr = new FakeElement('header', {
    top: rect.top,
    bottom: rect.top + headerHeight,
    left: rect.left,
    right: rect.right,
    width: rect.width,
    height: headerHeight,
  });
  sec.append(hdr);
  surface.append(sec);
  body.append(surface);

  if (!noFiber) {
    const wsProps = {};
    if (workspaceMainView !== undefined) wsProps.workspaceMainView = workspaceMainView;
    if (isWorkspaceVisible !== undefined) wsProps.isWorkspaceVisible = isWorkspaceVisible;
    if (activeTaskId) wsProps.activeTaskId = activeTaskId;
    const wsFiber = { tag: 0, memoizedProps: wsProps, return: null };
    const secProps = { 'data-workspace-conversation-frame': 'true' };
    const secFiber = { tag: 5, stateNode: sec, memoizedProps: secProps, return: wsFiber };
    sec[FIBER_KEY] = secFiber;
    sec[PROPS_KEY] = secProps;
    return { surface, sec, hdr, wsFiber, secFiber };
  }
  return { surface, sec, hdr, wsFiber: null, secFiber: null };
}

test('1. supports projects, timeline, unread (step 20), and pinned (never suppressed); degrades grouped ordinary rows and ignores side-frame', () => {
  const { sandbox, body } = createDomEnv();
  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');

  // Unread list with 22 tasks: 2 children before parent -> effectiveLimit = 22 (step 20)
  const unreadTasks = [
    { taskId: 'c1', title: 'Child 1', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'c2', title: 'Child 2', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' },
    ...Array.from({ length: 19 }, (_, i) => ({
      taskId: `u${i + 1}`,
      title: `Unread ${i + 1}`,
      workspacePath: '/ws1',
      hostId: 'local',
    })),
  ];
  const unreadFix = buildTaskListFixture({
    containerTestId: 'project-unread-tasks',
    kind: 'unread',
    tasks: unreadTasks,
    limit: 20,
  });
  aside.append(unreadFix.mountRoot);

  // Timeline list
  const timelineTasks = [
    { taskId: 'P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'c1', title: 'Child 1', workspacePath: '/ws1', hostId: 'local' },
  ];
  const timelineFix = buildTaskListFixture({
    containerTestId: 'project-timeline-tasks',
    kind: 'timeline',
    tasks: timelineTasks,
    limit: 20,
  });
  aside.append(timelineFix.mountRoot);

  // Pinned list (inside grouped view)
  const pinnedTasks = [
    { taskId: 'P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'c1', title: 'Child 1', workspacePath: '/ws1', hostId: 'local' },
  ];
  const pinnedFix = buildTaskListFixture({
    containerTestId: 'project-pinned-tasks',
    kind: 'pinned',
    tasks: pinnedTasks,
    limit: 5,
  });
  aside.append(pinnedFix.mountRoot);

  // Grouped ordinary row (div[role="button"][data-grouped-task-key]) must be ignored!
  const groupedWrap = new FakeElement('div');
  groupedWrap.setAttribute('data-testid', 'project-grouped-tasks');
  const groupedRow = new FakeElement('div');
  groupedRow.setAttribute('role', 'button');
  groupedRow.setAttribute('data-grouped-task-key', 'group-a:g1');
  groupedRow.setAttribute('data-testid', 'task-item-g1');
  groupedWrap.append(groupedRow);
  aside.append(groupedWrap);

  // Right-side subagent-directory must never be scanned/deduped
  const sideFrame = new FakeElement('aside');
  sideFrame.setAttribute('data-workspace-side-frame', 'true');
  const subDir = new FakeElement('div');
  subDir.setAttribute('data-testid', 'subagent-directory');
  const sideFix = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'side-1', title: 'Side Row', workspacePath: '/ws1', hostId: 'local' }],
    limit: 5,
  });
  subDir.append(sideFix.mountRoot);
  sideFrame.append(subDir);

  body.append(aside, sideFrame);

  const A = loadAdapter(sandbox);
  assert.equal(A.id, 'zcode-3.17.2');
  assert.equal(A.contractId, 'sidebar-list-v1');

  const mounts = A.findTaskMounts();
  assert.equal(mounts.some(m => m.kind === 'unread'), true);
  assert.equal(mounts.some(m => m.kind === 'timeline'), true);
  assert.equal(mounts.some(m => m.kind === 'pinned'), true);
  assert.equal(mounts.some(m => m.taskId === 'g1'), false, 'grouped ordinary div rows must be ignored');
  assert.equal(mounts.some(m => m.taskId === 'side-1'), false, 'right-side subagent-directory must be ignored');

  const st = A.selfTest();
  assert.equal(st.contractId, 'sidebar-list-v1');
  assert.equal(st.state, 'ready');
  assert.equal(st.capabilities.mount, true);
  assert.equal(st.capabilities.dedup, true);
  assert.equal(st.diagnostics.groupedOrdinaryDegraded, true);

  const pNode = { nodeId: 'nP', parentNodeId: null, sessionId: 'P', hostId: 'local', archived: false };
  const c1Node = { nodeId: 'nc1', parentNodeId: 'nP', sessionId: 'c1', hostId: 'local', archived: false };
  const c2Node = { nodeId: 'nc2', parentNodeId: 'nP', sessionId: 'c2', hostId: 'local', archived: false };
  const bySid = new Map([['P', pNode], ['c1', c1Node], ['c2', c2Node]]);
  const byNodeId = new Map([['nP', pNode], ['nc1', c1Node], ['nc2', c2Node]]);

  const unreadMounts = mounts.filter(m => m.kind === 'unread');
  const unreadDedup = A.suppressDuplicates(unreadMounts, bySid, byNodeId);
  assert.equal(unreadDedup.state, 'active');
  assert.equal(unreadDedup.L, 22);
  assert.equal(unreadMounts[0].wrapper.getAttribute('data-ss-suppressed'), '1');
  assert.equal(unreadMounts[1].wrapper.getAttribute('data-ss-suppressed'), '1');
  assert.equal(unreadMounts[2].wrapper.getAttribute('data-ss-suppressed'), null);

  const pinnedMounts = mounts.filter(m => m.kind === 'pinned');
  const pinnedDedup = A.suppressDuplicates(pinnedMounts, bySid, byNodeId);
  assert.equal(pinnedDedup.state, 'skipped:pinned');
  for (const pm of pinnedMounts) {
    assert.equal(pm.wrapper.getAttribute('data-ss-suppressed'), null, 'pinned rows must never be suppressed');
  }
});

test('2. empty list -> waiting vs broken hook/Fiber mismatch -> unsupported; grouped pinned-only stays ready', () => {
  // 2a. Empty list -> waiting
  {
    const { sandbox, body } = createDomEnv();
    const aside = new FakeElement('aside');
    aside.setAttribute('data-project-sidebar-panel', 'navigation');
    const emptyProj = new FakeElement('div');
    emptyProj.setAttribute('data-testid', 'virtual-project-tasks');
    aside.append(emptyProj);
    body.append(aside);

    const A = loadAdapter(sandbox);
    const st = A.selfTest();
    assert.equal(st.state, 'waiting');
    assert.equal(st.capabilities.mount, false);
    assert.equal(st.diagnostics.reason, 'empty_task_list');

    const sc = A.selfCheck();
    assert.equal(sc.sidebarFound, true);
    assert.equal(sc.octResolved, false);
    assert.equal(sc.navigatorResolved, false);
    assert.equal(sc.state, 'waiting');
    assert.equal(sc.contractId, 'sidebar-list-v1');
  }

  // 2b. Broken OCt/Fiber contract on visible <li> rows -> unsupported
  {
    const { sandbox, body } = createDomEnv();
    const aside = new FakeElement('aside');
    aside.setAttribute('data-project-sidebar-panel', 'navigation');
    const brokenFix = buildTaskListFixture({
      containerTestId: 'virtual-project-tasks',
      kind: 'project',
      tasks: [{ taskId: 't1', title: 'Task 1', workspacePath: '/ws1', hostId: 'local' }],
      brokenOCt: true,
    });
    aside.append(brokenFix.mountRoot);
    body.append(aside);

    const A = loadAdapter(sandbox);
    const st = A.selfTest();
    assert.equal(st.state, 'unsupported');
    assert.equal(st.capabilities.mount, false);
    assert.equal(st.diagnostics.reason, 'oct_contract_mismatch');
  }

  // 2c. Grouped view with pinned rows: pinned enhanced, ordinary grouped ignored -> ready
  {
    const { sandbox, body } = createDomEnv();
    const aside = new FakeElement('aside');
    aside.setAttribute('data-project-sidebar-panel', 'navigation');
    const pinnedFix = buildTaskListFixture({
      containerTestId: 'project-pinned-tasks',
      kind: 'pinned',
      tasks: [{ taskId: 'pin1', title: 'Pinned 1', workspacePath: '/ws1', hostId: 'local' }],
    });
    const groupedDiv = new FakeElement('div');
    groupedDiv.setAttribute('role', 'button');
    groupedDiv.setAttribute('data-grouped-task-key', 'grp-1:ord1');
    groupedDiv.setAttribute('data-testid', 'task-item-ord1');
    aside.append(pinnedFix.mountRoot, groupedDiv);
    body.append(aside);

    const A = loadAdapter(sandbox);
    const st = A.selfTest();
    assert.equal(st.state, 'ready');
    assert.equal(st.capabilities.mount, true);
    assert.equal(st.capabilities.navigation, true);
    assert.equal(st.capabilities.dedup, false);
    assert.equal(st.diagnostics.groupedOrdinaryDegraded, true);
  }
});

test('3. alternate Fiber resolution, workspace identity priority, multi-workspace instanceKey isolation, and non-local host exclusion', () => {
  const { sandbox, body } = createDomEnv();
  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');

  // Same taskId across two workspaces with data-project-workspace-identity (highest priority)
  const fixWsA = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'shared-sid', title: 'WS A', workspaceIdentity: 'task-fallback-a', hostId: 'local' }],
    sectionAttrs: {
      'data-project-id': 'proj-1',
      'data-project-host': 'local',
      'data-project-workspace-identity': 'ws-identity-alpha',
      'data-workspace-identity': 'legacy-should-lose',
    },
    useAlternate: true,
  });
  const fixWsB = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'shared-sid', title: 'WS B', workspaceIdentity: 'task-fallback-b', hostId: 'local' }],
    sectionAttrs: {
      'data-project-id': 'proj-1',
      'data-project-host': 'local',
      'data-project-workspace-identity': 'ws-identity-beta',
    },
  });
  // Legacy attribute fallback (data-workspace-identity without data-project-workspace-identity)
  const fixLegacy = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'shared-sid', title: 'Legacy', workspacePath: '/task-path', hostId: 'local' }],
    sectionAttrs: {
      'data-project-id': 'proj-1',
      'data-project-host': 'local',
      'data-workspace-identity': 'ws-identity-alpha',
    },
  });
  // Non-local host
  const fixRemote = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'shared-sid', title: 'Remote', workspacePath: '/remote', hostId: 'ssh-dev' }],
    sectionAttrs: {
      'data-project-id': 'proj-1',
      'data-project-host': 'ssh-dev',
      'data-project-workspace-identity': 'ws-identity-alpha',
    },
  });

  aside.append(fixWsA.mountRoot, fixWsB.mountRoot, fixLegacy.mountRoot, fixRemote.mountRoot);
  body.append(aside);

  const A = loadAdapter(sandbox);
  const mounts = A.findTaskMounts();
  assert.equal(mounts.length, 4, 'alternate Fiber must resolve just like current Fiber');

  const [mA, mB, mLegacy, mRemote] = mounts;
  assert.notEqual(mA.instanceKey, mB.instanceKey, 'distinct workspace identities must produce distinct instanceKeys');
  assert.equal(mA.instanceKey, mLegacy.instanceKey, 'data-project-workspace-identity takes priority over legacy and matches same hash');
  assert.notEqual(mA.instanceKey, mRemote.instanceKey, 'hostId must be part of instanceKey');
  assert.ok(mRemote.instanceKey.startsWith('ssh-dev:project:'));
  assert.ok(mA.instanceKey.startsWith('local:project:'));

  // Non-local host exclusion in navigation
  const navRemote = A.resolveNativeNavigator('shared-sid', [mRemote]);
  assert.equal(navRemote.ok, false);
  assert.equal(navRemote.code, 'NOT_IN_NATIVE_LIST');
});

test('4. chat viewport proof: settings inert, plugin-store/automations sized frame without chat proof hide Banner & block readActiveConversationId, chat restoration shows Banner', () => {
  const { sandbox, body } = createDomEnv();
  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');
  const projFix = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [
      { taskId: 'parent-1', title: 'Mother Chat', workspacePath: '/ws1', hostId: 'local' },
      { taskId: 'child-1', title: 'Child Chat', workspacePath: '/ws1', hostId: 'local' },
    ],
    activeTaskId: 'child-1',
    isWorkspaceActive: true,
    sectionAttrs: { 'data-project-id': 'p1', 'data-project-host': 'local' },
  });
  aside.append(projFix.mountRoot);

  // Start on plugin-store: sized conversation-frame, workspaceMainView='plugin-store'
  const frameObj = attachChatFrame(body, {
    workspaceMainView: 'plugin-store',
    isWorkspaceVisible: true,
    activeTaskId: 'child-1',
    inert: false,
  });
  body.append(aside);

  const A = loadAdapter(sandbox);
  const T = loadBundle(sandbox);
  T.update({
    schemaVersion: 1,
    storeInstanceId: 'st-1',
    projectionRevision: 1,
    nodes: [
      { nodeId: 'nP', parentNodeId: null, sessionId: 'parent-1', name: 'root', title: 'Mother Chat', hostId: 'local', workspacePath: '/ws1', createdAt: '1', comm: {} },
      { nodeId: 'nC', parentNodeId: 'nP', sessionId: 'child-1', name: 'child', title: 'Child Chat', hostId: 'local', workspacePath: '/ws1', createdAt: '2', indexState: 'indexed', comm: {} },
    ],
  });

  // 4a. plugin-store: positive rect, no chat proof -> viewport null, readActiveConversationId null, banner hidden
  assert.equal(A.resolveChatViewport(), null);
  assert.equal(A.readActiveConversationId(), null);
  let overlay = sandbox.document.getElementById('ss-overlay-root');
  assert.ok(!overlay || overlay.hidden === true, 'Banner must be hidden on plugin-store');
  assert.equal(A.selfTest().diagnostics.chatViewportReason, 'non_chat_view');

  // 4b. automations: positive rect, workspaceMainView='automations'
  frameObj.wsFiber.memoizedProps.workspaceMainView = 'automations';
  assert.equal(A.resolveChatViewport(), null);
  assert.equal(A.readActiveConversationId(), null);
  assert.equal(A.selfTest().diagnostics.chatViewportReason, 'non_chat_view');

  // 4c. unproven frame (workspaceMainView missing even if positive rect)
  delete frameObj.wsFiber.memoizedProps.workspaceMainView;
  assert.equal(A.resolveChatViewport(), null);
  assert.equal(A.readActiveConversationId(), null);
  assert.equal(A.selfTest().diagnostics.chatViewportReason, 'chat_view_unproven');

  // 4d. settings inert (even if workspaceMainView === 'chat')
  frameObj.wsFiber.memoizedProps.workspaceMainView = 'chat';
  frameObj.surface.setAttribute('data-root-workspace-surface', 'inert');
  frameObj.surface.setAttribute('inert', '');
  frameObj.surface.setAttribute('aria-hidden', 'true');
  frameObj.surface.classList.add('opacity-0');
  assert.equal(A.resolveChatViewport(), null);
  assert.equal(A.readActiveConversationId(), null);
  assert.equal(A.selfTest().diagnostics.chatViewportReason, 'inert_workspace');

  // 4e. restore chat view -> Banner becomes visible and readActiveConversationId returns 'child-1'
  frameObj.surface.removeAttribute('data-root-workspace-surface');
  frameObj.surface.removeAttribute('inert');
  frameObj.surface.removeAttribute('aria-hidden');
  frameObj.surface.classList.remove('opacity-0');
  const vp = A.resolveChatViewport();
  assert.ok(vp && vp.source === 'conversation-frame' && vp.top === 48);
  assert.equal(A.readActiveConversationId(), 'child-1');

  for (const fn of sandbox._winListeners.get('resize') || []) fn();
  overlay = sandbox.document.getElementById('ss-overlay-root');
  assert.ok(overlay && overlay.hidden === false, 'Banner must show when chat view is restored');
  assert.ok(overlay.textContent.includes('Mother Chat'));

  T.destroy();
});

test('5. spy test: selfTest() performs ZERO calls to onSelect, resumeSession, renameTask, syncUnindexedNodes, or queue.dispatch', () => {
  const { sandbox, body } = createDomEnv();
  let onSelectCalls = 0;
  let resumeCalls = 0;
  let renameCalls = 0;
  let syncCalls = 0;
  let dispatchCalls = 0;

  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');
  const services = {
    zcodeSessionService: {
      resumeSession: () => {
        resumeCalls++;
      },
    },
    zcodeTaskService: {
      renameTask: () => {
        renameCalls++;
      },
    },
  };
  const fix = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [
      { taskId: 'c1', title: 'Child', workspacePath: '/ws1', hostId: 'local' },
      { taskId: 'P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' },
    ],
    limit: 5,
    services,
    onSelect: () => {
      onSelectCalls++;
    },
    dispatchSpy: () => {
      dispatchCalls++;
    },
  });
  aside.append(fix.mountRoot);
  body.append(aside);
  attachChatFrame(body, { workspaceMainView: 'chat', isWorkspaceVisible: true });

  const A = loadAdapter(sandbox);
  const origSync = A.syncUnindexedNodes;
  A.syncUnindexedNodes = (...args) => {
    syncCalls++;
    return origSync(...args);
  };

  // Run selfTest in ready state
  const r1 = A.selfTest();
  assert.equal(r1.state, 'ready');
  assert.equal(r1.capabilities.dedup, true);

  // Also simulate dedup hook mismatch with leftover suppressed row and run selfTest
  fix.wrappers[0].wrapper.setAttribute('data-ss-suppressed', '1');
  fix.trFiber.memoizedState.next.memoizedState = 'broken'; // invalid h1
  const r2 = A.selfTest();
  assert.equal(r2.state, 'ready');
  assert.equal(r2.capabilities.dedup, false);
  assert.equal(fix.wrappers[0].wrapper.getAttribute('data-ss-suppressed'), null);

  A.selfCheck();

  assert.equal(onSelectCalls, 0);
  assert.equal(resumeCalls, 0);
  assert.equal(renameCalls, 0);
  assert.equal(syncCalls, 0);
  assert.equal(dispatchCalls, 0);
});

test('6. dedup circuit breaker and hook mismatch restore [data-ss-suppressed] and disable only dedup capability', () => {
  const { sandbox, body } = createDomEnv();
  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');

  const tasks = [
    { taskId: 'c1', title: 'Child', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'a', title: 'A', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'b', title: 'B', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'c', title: 'C', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' },
    { taskId: 'd', title: 'D', workspacePath: '/ws1', hostId: 'local' },
  ];
  // Use no-op dispatch so h0.memoizedState stays 5 and breaker trips after 5 attempts
  let dispatchCalls = 0;
  const fix = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks,
    limit: 5,
    services: { zcodeSessionService: { resumeSession: async () => {} } },
  });
  // Override dispatch so state doesn't converge, triggering breaker on 6th call
  fix.h0.queue.dispatch = () => {
    dispatchCalls++;
  };
  aside.append(fix.mountRoot);
  body.append(aside);
  attachChatFrame(body, { workspaceMainView: 'chat', isWorkspaceVisible: true });

  const A = loadAdapter(sandbox);
  const mounts = A.findTaskMounts();
  const pNode = { nodeId: 'nP', parentNodeId: null, sessionId: 'P', hostId: 'local', archived: false };
  const c1Node = { nodeId: 'nc1', parentNodeId: 'nP', sessionId: 'c1', hostId: 'local', archived: false };
  const bySid = new Map([['P', pNode], ['c1', c1Node]]);
  const byNodeId = new Map([['nP', pNode], ['nc1', c1Node]]);

  for (let i = 0; i < 5; i++) {
    const res = A.suppressDuplicates(mounts, bySid, byNodeId);
    assert.equal(res.state, 'active');
  }
  assert.equal(mounts[0].wrapper.getAttribute('data-ss-suppressed'), '1');

  const tripped = A.suppressDuplicates(mounts, bySid, byNodeId);
  assert.equal(tripped.state, 'disabled:breaker');
  assert.equal(mounts[0].wrapper.getAttribute('data-ss-suppressed'), null, 'breaker must unsuppress rows');

  const dispatchCountBeforeSelfTest = dispatchCalls;
  const st = A.selfTest();
  assert.equal(st.state, 'ready');
  assert.equal(st.capabilities.mount, true);
  assert.equal(st.capabilities.navigation, true);
  assert.equal(st.capabilities.chatViewport, true);
  assert.equal(st.capabilities.hostIndexSync, true);
  assert.equal(st.capabilities.dedup, false);
  assert.equal(st.diagnostics.dedupReason, 'disabled:breaker');
  assert.equal(dispatchCalls, dispatchCountBeforeSelfTest, 'selfTest must not call queue.dispatch');
});

test('7. bundle update(next) detects storeInstanceId changes at same projectionRevision, preserves non-destructive drainActions, exposes getStatus fields, and cleans up on destroy()', () => {
  const { sandbox, body } = createDomEnv();
  sandbox.__SS_TRANSPORT_OWNER__ = 'bridge';
  sandbox.__SS_BOOT_NONCE__ = 'nonce-xyz-123';

  const aside = new FakeElement('aside');
  aside.setAttribute('data-project-sidebar-panel', 'navigation');
  const fix = buildTaskListFixture({
    containerTestId: 'virtual-project-tasks',
    kind: 'project',
    tasks: [{ taskId: 'sid-P', title: 'Parent', workspacePath: '/ws1', hostId: 'local' }],
    activeTaskId: 'sid-C1',
    isWorkspaceActive: true,
    services: { zcodeSessionService: { resumeSession: async () => {} } },
    sectionAttrs: { 'data-project-id': 'p1', 'data-project-host': 'local' },
  });
  aside.append(fix.mountRoot);
  body.append(aside);
  attachChatFrame(body, { workspaceMainView: 'chat', isWorkspaceVisible: true, activeTaskId: 'sid-C1' });

  const A = loadAdapter(sandbox);
  const T = loadBundle(sandbox);

  const nodes1 = [
    { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Mother', hostId: 'local', workspacePath: '/ws1', createdAt: '1', revision: 1, comm: {} },
    { nodeId: 'nC1', parentNodeId: 'nP', sessionId: 'sid-C1', name: 'c1', title: 'Child 1', hostId: 'local', workspacePath: '/ws1', createdAt: '2', revision: 2, activeRunId: 'run-1', canCancel: true, canArchive: false, indexState: 'indexed', comm: {} },
  ];
  const upd1 = T.update({ schemaVersion: 1, storeInstanceId: 'store-A', projectionRevision: 5, nodes: nodes1 });
  assert.equal(upd1.ok, true);
  assert.equal(upd1.unchanged, undefined);
  const updSame = T.update({ schemaVersion: 1, storeInstanceId: 'store-A', projectionRevision: 5, nodes: nodes1 });
  assert.equal(updSame.ok, true);
  assert.equal(updSame.unchanged, true);

  // Non-destructive drainActions + ackActions with unmatched id keeps actionId
  const queued = T.enqueueAction('cancel_run', 'nC1');
  assert.ok(queued && queued.actionId);
  const d1 = T.drainActions();
  const d2 = T.drainActions();
  assert.equal(d1.length, 1);
  assert.equal(d2.length, 1);
  assert.equal(d1[0].actionId, d2[0].actionId);

  const badAck = T.ackActions([{ actionId: 'other-id', ok: false, code: 'IGNORED' }]);
  assert.equal(badAck.acked, 0);
  assert.equal(badAck.remaining, 1);
  assert.equal(T.drainActions()[0].actionId, queued.actionId);

  // Different storeInstanceId at SAME projectionRevision=5 must refresh & clear stale pending actions
  const nodes2 = [
    { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Mother', hostId: 'local', workspacePath: '/ws1', createdAt: '1', revision: 1, comm: {} },
    { nodeId: 'nC2', parentNodeId: 'nP', sessionId: 'sid-C2', name: 'c2', title: 'Child 2', hostId: 'local', workspacePath: '/ws1', createdAt: '3', revision: 1, canCancel: false, canArchive: true, indexState: 'indexed', comm: {} },
  ];
  const upd2 = T.update({ schemaVersion: 1, storeInstanceId: 'store-B', projectionRevision: 5, nodes: nodes2 });
  assert.equal(upd2.ok, true);
  assert.equal(upd2.unchanged, undefined, 'different storeInstanceId must NOT be treated as unchanged');
  assert.equal(T.drainActions().length, 0, 'stale actionQueue must be cleared on storeInstanceId change');

  const st = T.getStatus();
  assert.equal(st.contractId, 'sidebar-list-v1');
  assert.equal(st.storeInstanceId, 'store-B');
  assert.equal(st.projectionRevision, 5);
  assert.equal(st.transportOwner, 'bridge');
  assert.equal(st.bootNonce, 'nonce-xyz-123');
  assert.equal(st.pendingActions, 0);
  assert.equal(st.selfTest.state, 'ready');
  assert.equal(st.selfTest.capabilities.mount, true);
  assert.equal(st.selfTest.capabilities.chatViewport, true);

  T.destroy();
  assert.equal(sandbox.document.getElementById('ss-overlay-root'), null);
  assert.equal(sandbox.document.querySelectorAll('[data-ss-owned]').length, 0);
  assert.equal(sandbox.document.querySelectorAll('[data-ss-suppressed]').length, 0);
  assert.equal(sandbox.__SS_SIDEBAR_TREE__, undefined);
  assert.equal(sandbox.__SS_ZCODE_ADAPTER__, undefined);
  assert.equal(sandbox._intervals.size, 0);
});
