# zcode-side-sessions

**Claude Desktop 风格多会话树、隔离 Git Worktree 并行子任务与免改包常驻侧边栏树插件（面向 ZCode）**  
**Claude Desktop-Style Multi-Session Tree, Isolated Git Worktree Parallel Subtasks, and Zero-Patch Persistent Sidebar Tree Plugin for ZCode**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](./.zcode-plugin/plugin.json)
[![ZCode](https://img.shields.io/badge/ZCode-3.17.2%20--%203.18.2%20verified-8A2BE2.svg)](#适配与已验证版本--supported--verified-zcode-versions)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB.svg)](./requirements.lock)
[![Git](https://img.shields.io/badge/Git-%3E%3D2.38-F05032.svg)](#适配与已验证版本--supported--verified-zcode-versions)

[适配与已验证版本 / Supported Versions](#适配与已验证版本--supported--verified-zcode-versions) | [中文文档](#中文文档) | [English Documentation](#english-documentation)

---

## 适配与已验证版本 / Supported & Verified ZCode Versions

- **已验证宿主版本（Verified Desktop & CLI Versions）**：**ZCode Desktop `3.17.2` (`3.17.2.9661`) – `3.18.2` (`3.18.2.10443`)** 及配套 **ZCode CLI**（macOS Apple Silicon / Intel，`Python >= 3.11`，`Git >= 2.38`；核心 35 个 MCP 工具 + 5 个同步 Hooks + 11 个斜杠命令同时支持 Linux POSIX 环境）。
- **已验证构建与准入矩阵（Verified Build & Runtime Admission Matrix）**：

| ZCode 版本 / 构建 | 官方 `app.asar` SHA-256 | 侧边栏契约 (`contractId`) | 默认注入通道与签名状态 | 适配状态 |
| :--- | :--- | :--- | :--- | :--- |
| **ZCode Desktop `3.18.2` (`3.18.2.10443`)** | `236db1e6aeceb5fbbde3e28e69a3fcac4772c11787120efb41548e8d87c5ecb6` | `sidebar-list-v1` (`zcode-3.17.2`) | L1 主进程常驻桥（零改包、免重启、完整保留 Apple `codesign`） | **Verified（已实机验证）** |
| **ZCode Desktop `3.17.2` (`3.17.2.9661`)** | `12a2fc939df2fcb4188699772590f5151f1f2b90556bd34ecb6d44cf0d793cc6` | `sidebar-list-v1` (`zcode-3.17.2`) | L1 主进程常驻桥 / CDP（完整保留或可逆还原 Apple `codesign`） | **Verified（已实机验证）** |
| **未来官方版本（`ZCode 3.19.x+`）** | 运行时纯读动态校验 Apple 官方签名与 Electron Fuse | `sidebar-list-v1` 运行时只读 `selfTest()` | 契约驱动 `probation` 准入（逐项校验能力，失配自动安全降级） | **Contract Probation（自动自愈准入）** |

---

## 中文文档

### 1. 项目简介

`side-sessions` 是面向 **ZCode Desktop / ZCode CLI** 构建的生产级多会话树协调插件。它将单线性长对话升级为受严格事务与安全边界保护的 **`Parent -> Children` 多会话协作树**：主会话可同时派发最多 4 个长寿命子会话（只读调研沙箱或仓库外独立 Git Worktree 代码分支），支持跨回合状态持久化、长任务中途无损交接（Hand-off）、主子双向实时通信、零工作区污染的对象库代码合并（`git merge-tree` + `commit-tree`），以及 macOS ZCode 桌面端原位可折叠左侧边栏会话树增强。

插件核心运行时基于 **Python 3.11+ 标准库（零第三方 PyPI 依赖）** 与 SQLite WAL 事务存储构建，所有调用方身份均由宿主请求元数据 `params._meta["com.zcode/request-context"]` 强制绑定，杜绝参数注入与越权访问。

### 2. `v0.3.0` 更新亮点（ZCode `3.18.2` 全面适配与升级自愈）

1. **零改包、免重启 L1 主进程常驻桥（`ui/main_bridge.js`）与原子双向动作信箱**：
   - 通过单次瞬时 `SIGUSR1` 引导挂载幂等主进程常驻桥（基于公开 `process.getBuiltinModule("module").createRequire` 加载 Electron 并监听窗口创建与重载），引导完成后在 `finally` 中立即关闭临时回环调试端口（绝不关闭用户已有调试器），**全程零修改 `app.asar`、无需重启正在运行的 ZCode、100% 保留官方 Apple `codesign` 签名**，客户端升级或渲染页重载后自动恢复；
   - 配套有界原子文件信箱（`sidebar-ui/runtime/<appGen>/`），悬停快捷按钮动作（`cancel_run` / `archive_session`）经 `Engine.execute_ui_action` 落盘业务回执（`receipt`）后再精确触发 `ackActions`，每窗口强制单一 `transportOwner`（`bridge` 或 `cdp`）。
2. **契约驱动的 `probation` 运行时准入（`sidebar-list-v1`）**：
   - 纯读探针 `probe_runtime_build` 与严格 L3 补丁校验解耦，动态扫描定位 Electron Fuse sentinel 与开关位；未来升级至 ZCode `3.19.x+` 官方签名版本时不再受限于预注册 `app.asar` 哈希或历史残留补丁清单；
   - 适配器在运行时只读自检验证 `projects`、`timeline`、`unread`、`pinned` 列表挂载、活 React Fiber 正向聊天页证明（`workspaceMainView === "chat"`，彻底避免 `plugin-store` / `automations` / `settings` 页面误挂 `Parent Banner`）及分页不动点去重；`grouped` 视图平滑降级为仅 `pinned` 增强，右侧 `subagent-directory` 副栏严格隔离。
3. **ZCode `3.18.2` 原生 Session 工具防脑裂共存门禁（`native_session_guard`）**：
   - 与 ZCode `3.18.2` 新增的 12 个原生会话工具建立单一执行所有者边界：放行 `ListProjects`、`ListSessions`、`ReadSession`、`OpenSession`、`SetSessionPinned` 用于未受管会话发现、只读查阅、UI 跳转与置顶；
   - 通过确定性 `PreToolUse` 门禁在协调上下文默认拦截原生 `CreateSession` / `ForkSession`，并对插件受管节点拦截 `SendToSession` / `InterruptSession` / `SetSessionArchived` / `RenameSession`，配合 `SessionStart` 必注路由规则与受管连接 `appControlEnabled: false` 杜绝双轨脑裂。
4. **真实宿主反向 JSON-RPC 交互等待协议（`interaction/requestPermission` 与 `interaction/requestUserInput`）**：
   - 完整支持子会话 `app-server` stdio 反向请求按语义 `requestId` 停放、`server-N` 重公告去重（不重复生成等待或 `nonce`），对未授权 Provider / MCP 认证回调返回严格判别联合不可用响应；
   - 真人执行 `/side-sessions:respond` 时在证据哈希前完成精确协议规范化（`V4` 权限选项映射、`AskUserQuestion` 单问/多问 `answers`、`plan_approval` 与 `McpElicitation` schema 校验），经原连接回写后先置 `unknown`，待宿主真实 `permission.resolved` / `userInput.resolved` 事件到达后原子收敛为 `resolved` / `applied`。

### 3. 核心特性

- **Claude Desktop 风格父子会话树**：维护持久化家族拓扑（`Parent -> Children`）、共享上下文笔记、不可变阶段/终态报告与 SHA-256 校验产物引用（`ssref:v1:...`）。
- **每父会话 4 槽并发配额与显式派发组**：每个直接父节点拥有最多 **4 个并发执行槽（Slot 1..4）**，满槽立即确定性拒绝（`CAPACITY_EXCEEDED`）；支持通过 `create_dispatch_group` / `seal_dispatch_group` 编排批量并行扇出并在全组终态退出后汇总通知。
- **双模式工作区安全隔离**：
  - **`read_only` 白名单沙箱（`Workspace="inherit"`）**：共享父会话已核验工作目录，强制加载只读工具白名单，拦截文件写入、Shell 执行与可写委派绕过。
  - **`write_code` 仓库外独立 Git Worktree（`Workspace="branch"`）**：在源仓库外部受控目录 `~/.zcode/side-session-worktrees/<repo_key>/<node_uuid_hex>` 自动创建独立 Git Worktree 与 `side/<node_uuid_hex>` 分支，多个并行写任务互不干扰。
- **零污染 `merge-tree + commit-tree` 受控代码合并闭环**：
  - 先通过只读 `diff_worktree`（`/side-sessions:diff`）审查变更补丁并生成防篡改快照摘要 `preview_hash`；
  - 再由真人执行 `/side-sessions:merge` 触发 `UserPromptSubmit` Hook 同事务验真，交由后台守护在 Git 对象库预构造合并提交（支持 `ff-only`、`merge`、`squash`），冲突时父仓库工作区保持 **100% 干净**，合并后可选 `--cleanup` 一键安全回收 Worktree 并归档子节点。
- **主子双向通信与原生信箱实时插话**：
  - **主 -> 子**：支持持久化 FIFO 下一回合队列（`send_message_to_session`）、`~/.zcode/mailbox/` 运行中实时插话（含 10 分钟交互租约保护）及真人核验原连接等待响应（`/side-sessions:respond`）；
  - **子 -> 主**：支持 `report_child_turn` 结构化汇报、400 字首句结论摘要（`recap`）、进程退出兜底回执，以及同步 Hook `<side-sessions-event>` 安全边界注入。
- **macOS ZCode 左侧边栏原位可折叠树 UI 与自愈守护**：
  - 兼容 `Projects`、`Timeline`、`Unread`、`Pinned` 视图的原位父子缩进树、折叠箭头、未读计数徽章与顶层不动点去重；
  - 聊天主视图顶部自动挂载 **返回母对话悬浮横幅（Parent Banner）** 及一键快捷操作；
  - 单一 `com.zcode.side-sessions` LaunchAgent 独立监管后台调度器（`worker_runner.py`）与侧边栏注入器（`zcode_sidebar_injector.py`），支持免重启热切换与一键无损卸载还原。

### 4. 环境要求与跨平台兼容性

| 组件 | 要求说明 |
| :--- | :--- |
| **已验证宿主版本** | **ZCode Desktop `3.17.2` (`3.17.2.9661`) – `3.18.2` (`3.18.2.10443`)** 及 **ZCode CLI** |
| **Python** | `Python >= 3.11`（零第三方包依赖；插件内置 `scripts/run_py311.sh` 自动按序探测 Homebrew、pyenv、Framework 及系统 Python 3.11+；也可用环境变量 `ZCODE_SIDE_SESSIONS_PYTHON` 指定解释器绝对路径） |
| **Git** | `git >= 2.38`（`write_code` 分支隔离与 `git merge-tree --write-tree --name-only -z` 零污染合并所需） |
| **平台支持矩阵** | **核心 35 个 MCP 工具 + 5 个同步生命周期 Hooks + 11 个斜杠命令**：完整支持 **macOS（Apple Silicon / Intel）与 Linux**（POSIX）；<br>**左侧边栏原位 DOM 会话树 UI 注入**：已验证支持 **macOS ZCode Desktop `3.17.2` – `3.18.2`**，并对未来官方签名构建提供 `sidebar-list-v1` 契约 `probation` 自愈准入（UI 注入可选启用，不影响核心多会话与后台 Worker 运行）。 |

### 5. 安装方式（ZCode 插件市场一键安装）

本仓库采用符合 ZCode 官方规范的单插件扁平市场仓布局（顶层内置 `marketplace.json`，市场标识为 `side-sessions-marketplace`）：

1. 打开 ZCode 客户端，进入 **插件市场（Plugin Marketplace）**。
2. 点击 **添加（Add） -> 添加插件市场（Add Plugin Marketplace）**。
3. 粘贴本 GitHub 仓库地址并确认添加：
   ```text
   https://github.com/banana499/zcode-side-sessions
   ```
4. 切换到 **个人（Personal） -> `side-sessions-marketplace`**，找到 **多会话树与并行子任务 (Side Sessions)**（版本 `0.3.0`），点击 **安装（Install）** 并保持启用状态。
5. 新建一个对话任务即可直接使用 `/side-sessions:tree` 等全部斜杠命令、协调技能与 35 个 MCP 工具。

> **插件升级方式**：在插件市场右上角齿轮打开 **市场源（Marketplace Sources）**，刷新 `side-sessions-marketplace`，返回 **个人（Personal）** 点击 `side-sessions` 的 **更新（Update）** 即可。若已启用第 6 节的侧边栏 / LaunchAgent，升级后请使用新版本目录重新执行一次 `sidebar_ui_ctl.py install`，即可在不重启 ZCode 的前提下完成后台 Worker 与侧边栏常驻桥的平滑热切换；下文 `PLUGIN_DIR` 中的版本号目录随升级变化。

### 6. macOS 左侧边栏树 UI 启用、状态检查与无损卸载

> **兼容性说明**：核心 35 个 MCP 工具与同步 Hooks 安装插件后即刻在 macOS / Linux 跨平台生效；以下 `sidebar_ui_ctl.py` 命令用于在 **macOS ZCode Desktop（`3.17.2` – `3.18.2` 已验证）** 上启用原位左侧边栏可折叠会话树与常驻 `LaunchAgent` 守护。侧边栏功能要求 `ZCode.app` 安装在 `/Applications` 目录。

插件通过市场安装后，脚本位于 `~/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.3.0/scripts/sidebar_ui_ctl.py`：

```bash
# 定义脚本路径变量（使用插件内置 run_py311.sh 自动寻路 Python >= 3.11）
PLUGIN_DIR="$HOME/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.3.0"

# 1. 推荐默认方式（零修改应用包、免重启 ZCode、完整保留 Apple 官方签名）：
# 安装常驻 LaunchAgent 与侧边栏快照，自动通过一次性 SIGUSR1 引导挂载 L1 主进程常驻桥并立即关闭临时调试端口
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install

# 2. 检查守护进程与侧边栏注入实时状态（确认 injector.state == "READY" 且 transport == "bridge"）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" status

# 3. 临时关闭或重新开启侧边栏 DOM 树渲染（保留后台 Worker 守护）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" disable
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" enable

# 4. 可选备用通道（仅在目标环境禁用 SIGUSR1 inspector 时按需选用）：
# 备用 A：退出 ZCode 后以显式回环调试端口启动（免改包）
# /bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" start-zcode
# 备用 B：显式启用可逆 L3 ASAR 调试端口补丁（会修改 app.asar 并影响 codesign 校验，uninstall 可字节级还原）
# /bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install --cdp-patch

# 5. 一键无损卸载侧边栏增强（销毁主进程桥与页面控制器、移除 LaunchAgent、若曾打补丁则字节级还原官方原包，默认保留历史会话数据）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" uninstall
```

### 7. 斜杠命令速查表

| 斜杠命令 | 用法签名 | 核心功能说明 |
| :--- | :--- | :--- |
| `/side-sessions:tree` | `/side-sessions:tree [--archived]` | 查看当前家族父子会话树拓扑、槽位占用、分支状态、最新 400 字汇报摘要与待处理事件。 |
| `/side-sessions:handoff` | `/side-sessions:handoff <task_id>` | 将主会话已登记长任务的未完成计划（`remaining_plan`）两阶段安全移交给独立子会话继续推进。 |
| `/side-sessions:approve` | `/side-sessions:approve <proposal_id>`<br>`/side-sessions:approve context <op_id> <hash>` | 真人同事务核验并批准模型主动发起的子任务提案（自动排入后台启动队列）或降级上下文快照。 |
| `/side-sessions:dismiss` | `/side-sessions:dismiss <proposal_id>` | 取消并关闭处于等待批准状态的未启动子任务提案。 |
| `/side-sessions:continue` | `/side-sessions:continue <target> <message>` | 以显式恢复策略（`resume_policy="explicit"`）唤醒 `paused` 或 `done` 子会话并在原分支/上下文继续跟进。 |
| `/side-sessions:respond` | `/side-sessions:respond <wait_id> [answer...]` | 查看或经真人核验规范化回复处于 `waiting_input` 状态的子会话问题或权限请求。 |
| `/side-sessions:cancel` | `/side-sessions:cancel run <run_id> [reason]`<br>`/side-sessions:cancel message <msg_id> [reason]` | 安全终止运行中回合（确认进程树退出后释放槽位）或撤回尚未认领的排队消息。 |
| `/side-sessions:archive` | `/side-sessions:archive <target>` | 将空闲且无排队消息的子会话归档为 `archived`（完整保留历史报告与审计记录）。 |
| `/side-sessions:diff` | `/side-sessions:diff <session>` | 只读预览 `write_code` 子会话分支相对于基线的变更文件、补丁、可合并性及防篡改 `preview_hash`。 |
| `/side-sessions:merge` | `/side-sessions:merge <session> <preview_hash> [ff-only\|merge\|squash] [--cleanup]` | 核验 `preview_hash` 后通过对象库 `merge-tree` 零污染将子分支合并回父仓库，可选自动清理归档。 |
| `/side-sessions:cleanup` | `/side-sessions:cleanup <session>` | 独立安全清理干净的子会话磁盘 Worktree 并归档节点（未合并新提交自动保留 `side/<hex>` 分支引用）。 |

### 8. 典型协作工作流示例

#### 场景 A：多路隔离 Git Worktree 并行开发与零污染合并
1. **并行派发**：在主会话中指示模型：“请并行开启两个隔离写代码子会话，一个负责实现 `auth-token` 模块及单测，另一个负责重构 `rate-limiter` 中间件。”
2. **后台隔离执行**：主会话创建派发组并在 `~/.zcode/side-session-worktrees/` 下各自检出独立分支并行编码，主会话不阻塞，可随时对话或通过 `/side-sessions:tree` 查看进度。
3. **汇报与差异审查**：子会话完成后通过 `<side-sessions-event>` 回传 400 字结论摘要；执行：
   ```text
   /side-sessions:diff auth-token
   ```
   核对变更补丁、`merge_eligible: true` 及返回的 64 位 `preview_hash`。
4. **受控合并与清理**：确认无误后执行：
   ```text
   /side-sessions:merge auth-token <preview_hash> squash --cleanup
   ```
   后台守护在不污染父仓未跟踪文件的前提下完成原子合入、清理子 Worktree 目录并归档该节点。

#### 场景 B：长任务中途打断与无损交接（Hand-off）
1. 主会话正在执行已通过 `register_task` 登记的大规模重构任务，此时你需要主会话立刻排查线上紧急问题。
2. 执行 `/side-sessions:handoff <task_id>`（或直接要求主会话把当前任务移交后台子会话处理）。
3. 插件自动冻结原任务作用域、生成确定性历史截点投影并移交所有权给新子会话后台继续执行，主会话即刻释放出来响应紧急问题。

---

## English Documentation

### 1. Overview

`side-sessions` is a production-grade multi-session tree orchestration plugin for **ZCode Desktop and ZCode CLI**. It upgrades single-thread conversations into a transactional **`Parent -> Children` session hierarchy**: a parent session can run up to **4 concurrent child sessions** (either allowlisted `read_only` sandboxes or external isolated `write_code` Git worktrees), hand off long-running tasks mid-flight, exchange live bidirectional messages and structured reports, and merge isolated code branches back into the parent repository with zero working-tree pollution via `git merge-tree` + `git commit-tree`.

Built entirely on the **Python 3.11+ standard library (zero third-party runtime dependencies)** with an authoritative SQLite WAL state store, `side-sessions` binds caller identity strictly from host request metadata (`params._meta["com.zcode/request-context"]`) to prevent spoofing and cross-family privilege escalation.

### 2. What's New in `v0.3.0` (ZCode `3.18.2` Adaptation & Upgrade Self-Healing)

1. **Zero-ASAR-Patch, Zero-Restart L1 Persistent Main-Process Bridge (`ui/main_bridge.js`) + Atomic Action Mailbox**:
   - Automatically recovers across ZCode client upgrades and renderer reloads via a one-shot `SIGUSR1` bootstrap (`process.getBuiltinModule("module").createRequire` loading Electron in ESM main processes), immediately closing the temporary loopback inspector in `finally` (never closing any pre-existing user debugger) and **preserving official Apple `codesign` 100% intact with zero app restarts**;
   - Delivers hover action buttons (`cancel_run` / `archive_session`) through a bounded atomic file mailbox (`sidebar-ui/runtime/<appGen>/`) that invokes `ackActions` only after `Engine.execute_ui_action` writes a verified business `receipt`, enforcing a single `transportOwner` (`bridge` or `cdp`) per window.
2. **Contract-Driven `probation` Admission (`sidebar-list-v1`)**:
   - Decouples pure read-only `probe_runtime_build` + dynamic Electron Fuse sentinel discovery from strict L3 patch checks; future official Apple-signed ZCode `3.19.x+` releases no longer block on pre-registered `app.asar` SHA-256 hashes or stale `asar_patch.json` manifests;
   - Verifies each capability (`projects`, `timeline`, `unread`, `pinned`, positive live-Fiber `workspaceMainView === "chat"` proof for the chat `Parent Banner`, `(storeInstanceId, projectionRevision)` snapshot identity, and pagination fixpoint dedup) read-only at runtime (`grouped` view gracefully degrades to `pinned`-only enhancement, while right-hand `subagent-directory` side frames remain isolated).
3. **ZCode `3.18.2` Native Session Tools Coexistence (`native_session_guard`)**:
   - Prevents split-brain between `side-sessions` and ZCode `3.18.2`'s 12 native session tools: allows `ListProjects`, `ListSessions`, `ReadSession`, `OpenSession`, and `SetSessionPinned` for unmanaged session discovery, read-only inspection, UI navigation, and pinning;
   - Deterministically guards `CreateSession` / `ForkSession` in coordination context and `SendToSession` / `InterruptSession` / `SetSessionArchived` / `RenameSession` on plugin-managed nodes via `PreToolUse` (`continue: false`), backed by `SessionStart` routing reminders and `appControlEnabled: false` on managed `app-server` sessions.
4. **Reverse JSON-RPC Interaction Protocol (`interaction/requestPermission` & `interaction/requestUserInput`)**:
   - Parks real-host `app-server` stdio reverse requests by semantic `requestId`, deduplicates `server-N` re-announcements without regenerating waits or nonces, and returns strict discriminated-union unavailable replies for unauthorized provider/MCP auth callbacks (eliminating synthetic `{headers: {}}` replies);
   - Normalizes human `/side-sessions:respond` answers prior to evidence hashing (`V4` option responses, `AskUserQuestion` single/multi-question `answers`, `plan_approval`, and `McpElicitation` schema validation) and converges `unknown -> resolved / applied` upon real host `permission.resolved` and `userInput.resolved` events.

### 3. Key Features

- **Claude Desktop-Style Session Tree**: Persistent `Parent -> Children` hierarchy, shared family notes, immutable checkpoint/final reports, and SHA-256 verified chunked artifacts (`ssref:v1:...`).
- **4-Slot Concurrency Quota & Explicit Dispatch Groups**: Up to **4 concurrent active slots per direct parent**, enforced atomically with deterministic `CAPACITY_EXCEEDED` rejection when full, plus `create_dispatch_group` / `seal_dispatch_group` batch fan-out and completion manifests.
- **Dual Workspace Isolation**:
  - **`read_only` Allowlisted Sandbox (`Workspace="inherit"`)**: Shares the verified parent checkout under a strict read-only tool allowlist (blocks writes, arbitrary shell execution, and delegation bypasses).
  - **`write_code` External Git Worktree (`Workspace="branch"`)**: Provisions isolated Git worktrees outside the source checkout under `~/.zcode/side-session-worktrees/<repo_key>/<node_uuid_hex>` on dedicated `side/<node_uuid_hex>` branches.
- **Zero-Pollution `merge-tree + commit-tree` Merge Loop**:
  - Inspect changes and obtain a tamper-evident `preview_hash` via read-only `diff_worktree` (`/side-sessions:diff`);
  - Authorize integration via `/side-sessions:merge` (`ff-only`, `merge`, or `squash`). Commits are constructed in the Git object store via `git merge-tree --write-tree` + `git commit-tree` and fast-forwarded onto the parent branch—leaving the parent working tree **100% clean** even if conflicts occur.
- **Bidirectional Communication & Live Mailbox Interjection**:
  - **Parent -> Child**: Durable FIFO next-turn queues (`send_message_to_session`), live mid-turn steering via `~/.zcode/mailbox/` with 10-minute interactive leases, and human-verified wait responses (`/side-sessions:respond`).
  - **Child -> Parent**: Structured `report_child_turn` receipts, lead-sentence 400-character recaps, exit fallback summaries, and synchronous `<side-sessions-event>` Hook delivery.
- **macOS In-Place Collapsible Sidebar Tree UI & Self-Healing Daemon**:
  - Renders collapsible parent-child trees directly inside ZCode's left sidebar across `Projects`, `Timeline`, `Unread`, and `Pinned` views with fixpoint top-level deduplication and unread badges;
  - Mounts a floating **Return to Parent Session (`Parent Banner`)** header exclusively on active chat views;
  - Supervised by a single `com.zcode.side-sessions` LaunchAgent managing both `worker_runner.py` and `zcode_sidebar_injector.py` with zero-restart hot-reload release staging and one-click lossless uninstallation.

### 4. Requirements & Platform Matrix

- **Verified Host Versions**: **ZCode Desktop `3.17.2` (`3.17.2.9661`) – `3.18.2` (`3.18.2.10443`)** and **ZCode CLI**
- **Python**: `Python >= 3.11` (zero third-party PyPI packages; built-in `scripts/run_py311.sh` automatically locates Homebrew, pyenv, framework, or system Python 3.11+; set `ZCODE_SIDE_SESSIONS_PYTHON` to an absolute interpreter path to override)
- **Git**: `git >= 2.38` (required for `git merge-tree --write-tree --name-only -z`)
- **Platform Support**:
  - **Core 35 MCP Tools + 5 Synchronous Hooks + 11 Slash Commands**: Cross-platform **macOS (Apple Silicon / Intel) and Linux** (POSIX).
  - **In-Place Left Sidebar DOM Tree UI**: Verified on **macOS ZCode Desktop `3.17.2` – `3.18.2`**, with contract-driven `sidebar-list-v1` `probation` admission for future official signed builds (optional enhancement; core session orchestration works without UI injection). Requires `ZCode.app` installed in `/Applications`.

### 5. Installation (ZCode Plugin Marketplace)

1. Open **Plugin Marketplace** in ZCode.
2. Click **Add -> Add Plugin Marketplace**.
3. Enter the GitHub repository URL:
   ```text
   https://github.com/banana499/zcode-side-sessions
   ```
4. Open **Personal -> `side-sessions-marketplace`**, select **Side Sessions** (`v0.3.0`), and click **Install**.
5. Start a new conversation task to access all `/side-sessions:*` slash commands, skills, and MCP tools.

### 6. macOS Sidebar Tree UI Setup, Status & Lossless Uninstall

After installing via the marketplace, manage the optional macOS sidebar UI and LaunchAgent using `sidebar_ui_ctl.py`:

> **Upgrading**: after updating the plugin in the marketplace, re-run `sidebar_ui_ctl.py install` from the new version directory if you enabled the sidebar / LaunchAgent—it hot-swaps the worker and L1 persistent main-process bridge in place without restarting ZCode. The version segment in `PLUGIN_DIR` changes with each release.

```bash
PLUGIN_DIR="$HOME/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.3.0"

# 1. Recommended default (zero app bundle edits, zero ZCode restart, preserves official Apple codesign):
# Stages the sidebar snapshot, loads LaunchAgent, and bootstraps the L1 persistent main-process bridge via one-shot SIGUSR1
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install

# 2. Verify daemon & sidebar injector health (expect injector.state == "READY" and transport == "bridge")
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" status

# 3. Temporarily disable or re-enable sidebar DOM rendering while keeping the background worker running
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" disable
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" enable

# 4. Optional fallback modes (only needed if SIGUSR1 inspector is unavailable in a custom build):
# Fallback A: quit ZCode (Cmd+Q) first, then launch with an explicit loopback debug port (zero bundle edits)
# /bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" start-zcode
# Fallback B: opt-in reversible L3 ASAR debug-port patch (modifies app.asar and invalidates codesign until uninstall)
# /bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install --cdp-patch

# 5. One-click lossless uninstall (disposes live main-process bridge & DOM controller, removes LaunchAgent, restores any patched bytes)
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" uninstall
```

### 7. Slash Commands Reference

| Command | Signature | Description |
| :--- | :--- | :--- |
| `/side-sessions:tree` | `/side-sessions:tree [--archived]` | Display the family session tree, slot usage, worktree branches, 400-char recaps, and pending events. |
| `/side-sessions:handoff` | `/side-sessions:handoff <task_id>` | Perform a guarded two-phase handoff of a registered task's `remaining_plan` to a child session. |
| `/side-sessions:approve` | `/side-sessions:approve <proposal_id>`<br>`/side-sessions:approve context <op_id> <hash>` | Authorize a pending child proposal (queued automatically for background launch) or degraded context snapshot. |
| `/side-sessions:dismiss` | `/side-sessions:dismiss <proposal_id>` | Dismiss an unstarted proposal (`waiting_user` / `awaiting_brief` / `approved`). |
| `/side-sessions:continue` | `/side-sessions:continue <target> <message>` | Explicitly wake a `paused` or `done` child session and enqueue a follow-up prompt on the same node. |
| `/side-sessions:respond` | `/side-sessions:respond <wait_id> [answer...]` | Inspect or submit a normalized, human-verified answer/decision to an open `waiting_input` request. |
| `/side-sessions:cancel` | `/side-sessions:cancel run <run_id> [reason]`<br>`/side-sessions:cancel message <msg_id> [reason]` | Stop an active run (releasing its slot only after confirmed process exit) or cancel a queued message. |
| `/side-sessions:archive` | `/side-sessions:archive <target>` | Archive an idle child session while preserving all reports, events, and audit records. |
| `/side-sessions:diff` | `/side-sessions:diff <session>` | Preview `write_code` branch changes, conflict checks, merge eligibility, and `preview_hash`. |
| `/side-sessions:merge` | `/side-sessions:merge <session> <preview_hash> [ff-only\|merge\|squash] [--cleanup]` | Verify `preview_hash` and merge a child worktree cleanly via `git merge-tree` + `commit-tree`. |
| `/side-sessions:cleanup` | `/side-sessions:cleanup <session>` | Safely remove a clean child worktree directory and archive the node without losing unmerged commits. |

### 8. Verification Suite

```bash
# 1. JavaScript syntax checks for main-process bridge, sidebar adapter, and tree bundle
node --check ./ui/adapters/zcode-3.17.2.js && node --check ./ui/sidebar_tree_bundle.js && node --check ./ui/main_bridge.js

# 2. Sidebar DOM fixpoint deduplication & sidebar-list-v1 adapter contract suites (14 tests)
node ./tests/sidebar-ui/fixpoint.test.mjs
node --test ./tests/sidebar-ui/adapter_contract.test.mjs

# 3. Full deterministic Python unit, runtime bridge, and ZCode 3.18.2 protocol test suites (106 tests)
/bin/sh ./scripts/run_py311.sh -m unittest discover -s ./tests -v

# 4. Worker end-to-end self-verification probes
/bin/sh ./scripts/run_py311.sh ./scripts/worker_runner.py verify --json
```

---

## License

Released under the [MIT License](./LICENSE). Copyright (c) 2026 `banana499`.
