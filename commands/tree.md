---
description: 查看当前父子会话树拓扑、节点状态、工作区分支、最新汇报摘要及待处理事件（用法：/side-sessions:tree [--archived]）
---

# `/side-sessions:tree [--archived]`

展示当前会话所在授权家族（family）的父子会话树、提案队列、派发组与待处理事件状态。

## 参数说明

- `--archived`（可选）：默认仅展示 `active`、`paused`、`done` 状态的会话节点；传入 `--archived` 时将 `include_archived=true`，一并展示已归档（`archived`）节点。
- **安全约束**：调用方身份严格由宿主请求元数据（`CallerContext`）绑定，严禁接受命令参数注入伪造的 `caller_sid` 或越界查询其他 family 的节点。

## 执行步骤

1. **解析命令参数**：
   - 检查用户输入参数是否包含 `--archived`。若包含则设置 `include_archived = true`，否则设置 `include_archived = false`。
   - 若用户传入了未知标志或试图通过参数覆盖调用者身份，立即拒绝并提示正确用法：`/side-sessions:tree [--archived]`。
2. **调用 `list_sessions` 工具**：
   - 调用 `list_sessions(linked=true, include_archived=<bool>)`。
   - 如需补充特定节点的等待项或异步操作细节，可按需对活动节点调用 `get_session(session_id=<node_id>)`。
3. **结构化渲染会话树**：
   - **拓扑层级（`Parent -> Children`）**：按父子缩进树状展示每个节点的逻辑 `node_id`、安全短名称 `name`、标题 `title` 及对应的 `runtime_session_id`。
   - **双重状态与恢复标记**：分别展示节点状态（`node_status`: `active` | `paused` | `done` | `archived`）、当前回合执行状态（`execution_state`: `queued` | `starting` | `running` | `waiting_input` | `stopping` | `exited` | `failed` | `cancelled` | `reconciliation`）与恢复状态（`recovery_status`）。
   - **上下文与工作区隔离**：展示 `context_requested` -> `context_applied`（如 `fork -> summary_copy`）、`workspace_mode`（`inherit` 或 `branch` 及对应 `side/<node_uuid_hex>` 分支）以及 `host_link_verified` 布尔核验状态。
   - **最新汇报与待办计数**：展示节点的 400 字符最新摘要 `last_turn_report`、未确认事件数（`pending_event_count`）、开放等待请求摘要（`wait_summaries`）以及待批准提案（`waiting_user` / `awaiting_brief`）或待质量确认操作（`awaiting_context_acceptance`）。
   - **操作指引**：若存在待确认事件、待批准提案或开放等待项，在末尾给出对应的后续命令提示（如 `/side-sessions:approve`、`/side-sessions:respond` 或调用 `read_report` / `ack_events`）。
