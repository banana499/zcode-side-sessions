# zcode-side-sessions

**Claude Desktop 风格多会话树、隔离 Git Worktree 并行子任务与原位可折叠侧边栏插件（面向 ZCode）**  
**Claude Desktop-Style Multi-Session Tree, Isolated Git Worktree Parallel Subtasks, and Collapsible Sidebar Tree Plugin for ZCode**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](./.zcode-plugin/plugin.json)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB.svg)](./requirements.lock)
[![Git](https://img.shields.io/badge/Git-%3E%3D2.40-F05032.svg)](#环境要求--requirements)

[中文文档](#中文文档) | [English Documentation](#english-documentation)

---

## 中文文档

### 1. 项目简介

`side-sessions` 是面向 **ZCode Desktop / ZCode CLI** 构建的生产级多会话树协调插件。它将单线性长对话升级为受严格事务与安全边界保护的 **`Parent -> Children` 多会话协作树**：主会话可同时派发最多 4 个长寿命子会话（只读调研沙箱或仓库外独立 Git Worktree 代码分支），支持跨回合状态持久化、长任务中途无损交接（Hand-off）、主子双向实时通信、零工作区污染的对象库代码合并（`git merge-tree` + `commit-tree`），以及 macOS ZCode 桌面端原位可折叠左侧边栏会话树增强。

插件核心运行时基于 **Python 3.11+ 标准库（零第三方 PyPI 依赖）** 与 SQLite WAL 事务存储构建，所有调用方身份均由宿主请求元数据 `params._meta["com.zcode/request-context"]` 强制绑定，杜绝参数注入与越权访问。

### 2. 核心特性

- **Claude Desktop 风格父子会话树**：维护持久化家族拓扑（`Parent -> Children`）、共享上下文笔记、不可变阶段/终态报告与 SHA-256 校验产物引用（`ssref:v1:...`）。
- **每父会话 4 槽并发配额与显式派发组**：每个直接父节点拥有最多 **4 个并发执行槽（Slot 1..4）**，满槽立即确定性拒绝（`CAPACITY_EXCEEDED`）；支持通过 `create_dispatch_group` / `seal_dispatch_group` 编排批量并行扇出并在全组终态退出后汇总通知。
- **双模式工作区安全隔离**：
  - **`read_only` 白名单沙箱（`Workspace="inherit"`）**：共享父会话已核验工作目录，强制加载只读工具白名单，拦截文件写入、Shell 执行与可写委派绕过。
  - **`write_code` 仓库外独立 Git Worktree（`Workspace="branch"`）**：在源仓库外部受控目录 `~/.zcode/side-session-worktrees/<repo_key>/<node_uuid_hex>` 自动创建独立 Git Worktree 与 `side/<node_uuid_hex>` 分支，多个并行写任务互不干扰。
- **零污染 `merge-tree + commit-tree` 受控代码合并闭环**：
  - 先通过只读 `diff_worktree`（`/side-sessions:diff`）审查变更补丁并生成防篡改快照摘要 `preview_hash`；
  - 再由真人执行 `/side-sessions:merge` 触发 `UserPromptSubmit` Hook 同事务验真，交由后台守护在 Git 对象库预构造合并提交（支持 `ff-only`、`merge`、`squash`），冲突时父仓库工作区保持 **100% 干净**，合并后可选 `--cleanup` 一键安全回收 Worktree 并归档子节点。
- **主子双向通信与原生信箱实时插话**：
  - **主 -> 子**：支持持久化 FIFO 下一回合队列（`send_message_to_session`）、`~/.zcode/mailbox/` 运行中实时插话（含 10 分钟交互租约保护）及原连接等待响应（`/side-sessions:respond`）；
  - **子 -> 主**：支持 `report_child_turn` 结构化汇报、400 字首句结论摘要（`recap`）、进程退出兜底回执，以及同步 Hook `<side-sessions-event>` 安全边界注入。
- **macOS ZCode 左侧边栏原位可折叠树 UI 与自愈守护**：
  - 兼容 `Projects`、`Timeline`、`Pinned` 视图的原位父子缩进树、折叠箭头、未读计数徽章与顶层不动点去重；
  - 子会话视图顶部自动挂载 **返回母对话悬浮横幅（Parent Banner）** 及一键快捷操作；
  - 单一 `com.zcode.side-sessions` LaunchAgent 独立监管后台调度器（`worker_runner.py`）与侧边栏注入器（`zcode_sidebar_injector.py`），支持免重启热切换与一键无损卸载还原。

### 3. 环境要求与跨平台兼容性

| 组件 | 要求说明 |
| :--- | :--- |
| **宿主环境** | ZCode Desktop 或 ZCode CLI |
| **Python** | `Python >= 3.11`（零第三方包依赖；插件内置 `scripts/run_py311.sh` 自动按序探测 Homebrew、pyenv、Framework 及系统 Python 3.11+） |
| **Git** | `git >= 2.40`（`write_code` 分支隔离与 `git merge-tree --write-tree` 零污染合并所需） |
| **平台支持矩阵** | **核心 35 个 MCP 工具 + 5 个同步生命周期 Hooks + 11 个斜杠命令**：完整支持 **macOS 与 Linux**（POSIX）；<br>**左侧边栏原位 DOM 会话树 UI 注入**：当前适配 **macOS ZCode Desktop 3.17.2**（UI 注入可选启用，不影响核心多会话与后台 Worker 运行）。 |

### 4. 安装方式（ZCode 插件市场一键安装）

本仓库采用符合 ZCode 官方规范的单插件扁平市场仓布局（顶层内置 `marketplace.json`，市场标识为 `side-sessions-marketplace`）：

1. 打开 ZCode 客户端，进入 **插件市场（Plugin Marketplace）**。
2. 点击 **添加（Add） -> 添加插件市场（Add Plugin Marketplace）**。
3. 粘贴本 GitHub 仓库地址并确认添加：
   ```text
   https://github.com/banana499/zcode-side-sessions
   ```
4. 切换到 **个人（Personal） -> `side-sessions-marketplace`**，找到 **多会话树与并行子任务 (Side Sessions)**（版本 `0.2.0`），点击 **安装（Install）** 并保持启用状态。
5. 新建一个对话任务即可直接使用 `/side-sessions:tree` 等全部斜杠命令、协调技能与 35 个 MCP 工具。

> **插件升级方式**：在插件市场右上角齿轮打开 **市场源（Marketplace Sources）**，刷新 `side-sessions-marketplace`，返回 **个人（Personal）** 点击 `side-sessions` 的 **更新（Update）** 即可。

### 5. macOS 左侧边栏树 UI 启用、状态检查与无损卸载

> **兼容性说明**：核心 35 个 MCP 工具与同步 Hooks 安装插件后即刻在 macOS / Linux 跨平台生效；以下 `sidebar_ui_ctl.py` 命令仅用于在 **macOS ZCode Desktop 3.17.2** 上启用原位左侧边栏可折叠会话树与常驻 `LaunchAgent` 守护。

插件通过市场安装后，脚本位于 `~/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.2.0/scripts/sidebar_ui_ctl.py`：

```bash
# 定义脚本路径变量（使用插件内置 run_py311.sh 自动寻路 Python >= 3.11）
PLUGIN_DIR="$HOME/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.2.0"

# 1. 安装常驻 LaunchAgent 与侧边栏发布快照
# 方式 A（免修改应用包）：配合带调试端口启动的 ZCode 使用
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" start-zcode

# 方式 B（支持 Dock 直接启动 ZCode 3.17.2）：启用可逆 ASAR 调试端口补丁（自动备份原始摘要与字节）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install --cdp-patch

# 2. 检查守护进程与侧边栏注入实时状态（确认 injector.state == "READY"）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" status

# 3. 临时关闭或重新开启侧边栏 DOM 树渲染（保留后台 Worker 守护）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" disable
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" enable

# 4. 一键无损卸载侧边栏增强（销毁页面内存控制器、移除 LaunchAgent 并字节级还原官方原包签名，默认保留历史会话数据）
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" uninstall
```

### 6. 斜杠命令速查表

| 斜杠命令 | 用法签名 | 核心功能说明 |
| :--- | :--- | :--- |
| `/side-sessions:tree` | `/side-sessions:tree [--archived]` | 查看当前家族父子会话树拓扑、槽位占用、分支状态、最新 400 字汇报摘要与待处理事件。 |
| `/side-sessions:handoff` | `/side-sessions:handoff <task_id>` | 将主会话已登记长任务的未完成计划（`remaining_plan`）两阶段安全移交给独立子会话继续推进。 |
| `/side-sessions:approve` | `/side-sessions:approve <proposal_id>`<br>`/side-sessions:approve context <op_id> <hash>` | 真人同事务核验并批准模型主动发起的子任务提案（自动排入后台启动队列）或降级上下文快照。 |
| `/side-sessions:dismiss` | `/side-sessions:dismiss <proposal_id>` | 取消并关闭处于等待批准状态的未启动子任务提案。 |
| `/side-sessions:continue` | `/side-sessions:continue <target> <message>` | 以显式恢复策略（`resume_policy="explicit"`）唤醒 `paused` 或 `done` 子会话并在原分支/上下文继续跟进。 |
| `/side-sessions:respond` | `/side-sessions:respond <wait_id> [answer...]` | 查看或经真人核验直接回复处于 `waiting_input` 状态的子会话问题或权限请求。 |
| `/side-sessions:cancel` | `/side-sessions:cancel run <run_id> [reason]`<br>`/side-sessions:cancel message <msg_id> [reason]` | 安全终止运行中回合（确认进程树退出后释放槽位）或撤回尚未认领的排队消息。 |
| `/side-sessions:archive` | `/side-sessions:archive <target>` | 将空闲且无排队消息的子会话归档为 `archived`（完整保留历史报告与审计记录）。 |
| `/side-sessions:diff` | `/side-sessions:diff <session>` | 只读预览 `write_code` 子会话分支相对于基线的变更文件、补丁、可合并性及防篡改 `preview_hash`。 |
| `/side-sessions:merge` | `/side-sessions:merge <session> <preview_hash> [ff-only\|merge\|squash] [--cleanup]` | 核验 `preview_hash` 后通过对象库 `merge-tree` 零污染将子分支合并回父仓库，可选自动清理归档。 |
| `/side-sessions:cleanup` | `/side-sessions:cleanup <session>` | 独立安全清理干净的子会话磁盘 Worktree 并归档节点（未合并新提交自动保留 `side/<hex>` 分支引用）。 |

### 7. 典型协作工作流示例

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

### 2. Key Features

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
  - Renders collapsible parent-child trees directly inside ZCode's left sidebar across `Projects`, `Timeline`, and `Pinned` views with fixpoint top-level deduplication and unread badges;
  - Mounts a floating **Return to Parent Session (`Parent Banner`)** header inside child sessions;
  - Supervised by a single `com.zcode.side-sessions` LaunchAgent managing both `worker_runner.py` and `zcode_sidebar_injector.py` with hot-reload release staging and one-click lossless uninstallation.

### 3. Requirements & Platform Matrix

- **Host**: ZCode Desktop or ZCode CLI
- **Python**: `Python >= 3.11` (zero third-party PyPI packages; built-in `scripts/run_py311.sh` automatically locates Homebrew, pyenv, framework, or system Python 3.11+)
- **Git**: `git >= 2.40` (required for `git merge-tree --write-tree`)
- **Platform Support**:
  - **Core 35 MCP Tools + 5 Synchronous Hooks + 11 Slash Commands**: Cross-platform **macOS and Linux** (POSIX).
  - **In-Place Left Sidebar DOM Tree UI**: Currently tailored for **macOS ZCode Desktop 3.17.2** (optional enhancement; core session orchestration works without UI injection).

### 4. Installation (ZCode Plugin Marketplace)

1. Open **Plugin Marketplace** in ZCode.
2. Click **Add -> Add Plugin Marketplace**.
3. Enter the GitHub repository URL:
   ```text
   https://github.com/banana499/zcode-side-sessions
   ```
4. Open **Personal -> `side-sessions-marketplace`**, select **Side Sessions** (`v0.2.0`), and click **Install**.
5. Start a new conversation task to access all `/side-sessions:*` slash commands, skills, and MCP tools.

### 5. macOS Sidebar Tree UI Setup, Status & Lossless Uninstall

After installing via the marketplace, manage the optional macOS sidebar UI and LaunchAgent using `sidebar_ui_ctl.py`:

```bash
PLUGIN_DIR="$HOME/.zcode/cli/plugins/cache/side-sessions-marketplace/side-sessions/0.2.0"

# Install LaunchAgent & stage sidebar UI snapshot (Option A: launch ZCode with debug port, zero app bundle edits)
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" start-zcode

# Option B (macOS ZCode 3.17.2 Dock launch): opt-in reversible ASAR debug-port patch with SHA-verified backup
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" install --cdp-patch

# Verify daemon & sidebar injector health (expect injector.state == "READY")
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" status

# One-click lossless uninstall (destroys live DOM controller, removes LaunchAgent, restores original ZCode.app bytes)
/bin/sh "$PLUGIN_DIR/scripts/run_py311.sh" "$PLUGIN_DIR/scripts/sidebar_ui_ctl.py" uninstall
```

### 6. Slash Commands Reference

| Command | Signature | Description |
| :--- | :--- | :--- |
| `/side-sessions:tree` | `/side-sessions:tree [--archived]` | Display the family session tree, slot usage, worktree branches, 400-char recaps, and pending events. |
| `/side-sessions:handoff` | `/side-sessions:handoff <task_id>` | Perform a guarded two-phase handoff of a registered task's `remaining_plan` to a child session. |
| `/side-sessions:approve` | `/side-sessions:approve <proposal_id>`<br>`/side-sessions:approve context <op_id> <hash>` | Authorize a pending child proposal (queued automatically for background launch) or degraded context snapshot. |
| `/side-sessions:dismiss` | `/side-sessions:dismiss <proposal_id>` | Dismiss an unstarted proposal (`waiting_user` / `awaiting_brief` / `approved`). |
| `/side-sessions:continue` | `/side-sessions:continue <target> <message>` | Explicitly wake a `paused` or `done` child session and enqueue a follow-up prompt on the same node. |
| `/side-sessions:respond` | `/side-sessions:respond <wait_id> [answer...]` | Inspect or submit a human-verified answer/decision to an open `waiting_input` request. |
| `/side-sessions:cancel` | `/side-sessions:cancel run <run_id> [reason]`<br>`/side-sessions:cancel message <msg_id> [reason]` | Stop an active run (releasing its slot only after confirmed process exit) or cancel a queued message. |
| `/side-sessions:archive` | `/side-sessions:archive <target>` | Archive an idle child session while preserving all reports, events, and audit records. |
| `/side-sessions:diff` | `/side-sessions:diff <session>` | Preview `write_code` branch changes, conflict checks, merge eligibility, and `preview_hash`. |
| `/side-sessions:merge` | `/side-sessions:merge <session> <preview_hash> [ff-only\|merge\|squash] [--cleanup]` | Verify `preview_hash` and merge a child worktree cleanly via `git merge-tree` + `commit-tree`. |
| `/side-sessions:cleanup` | `/side-sessions:cleanup <session>` | Safely remove a clean child worktree directory and archive the node without losing unmerged commits. |

### 7. Verification Suite

```bash
# 1. Run full deterministic Python unit test suite (71 tests)
/bin/sh ./scripts/run_py311.sh -m unittest discover -s ./tests -v

# 2. Run sidebar DOM fixpoint deduplication tests
node ./tests/sidebar-ui/fixpoint.test.mjs

# 3. Run worker end-to-end self-verification probes
/bin/sh ./scripts/run_py311.sh ./scripts/worker_runner.py verify --json
```

---

## License

Released under the [MIT License](./LICENSE). Copyright (c) 2026 `banana499`.
