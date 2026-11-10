---
description: 归档已停止且无未决启动或排队消息的子会话节点（用法：/side-sessions:archive <target>）
---

# `/side-sessions:archive <target>`

在确认目标子会话无活动执行器且无未决启动/排队任务的前提下，将其节点状态归档为 `archived`。

## 参数说明

- `<target>`（必填）：待归档的子会话逻辑 `node_id`（UUID）或当前授权 family 内无歧义的安全短名称 `name`。

## 归档安全与数据保留规范

- **忙碌会话禁止直接归档（`SESSION_BUSY`）**：
  - 当目标会话仍存在活动执行器（`starting` / `running` / `waiting_input` / `stopping`）、未决启动操作（`preparing_context` / `awaiting_context_acceptance` / `reserved`）或尚未处理的 `queued` 排队消息时，`archive_session` 会拒绝并返回 `SESSION_BUSY`。
  - 遇到 `SESSION_BUSY` 时，必须先对活动回合调用 `/side-sessions:cancel run <run_id>` 并验证 `exit_confirmed == true`，同时对所有排队消息显式调用 `/side-sessions:cancel message <message_id>` 清空队列后，方可再次执行归档。
- **归档不删除审计事实与工作区**：
  - 归档仅将 `node_status` 置为 `archived`（禁止后续隐式恢复或新派发；首版无解档工具）。
  - 归档**不会删除**该节点的历史报告（`reports`）、未确认或已确认事件（`outbox`）、共享笔记（`notes`）及独立 Git worktree（`worktrees`）；父节点仍可通过 `read_report`、`read_artifact` 与 `ack_events` 完成读取与确认闭环。

## 执行步骤

1. **查询目标会话当前状态与版本号（`get_session`）**：
   - 若 `<target>` 为短名，先通过 `list_sessions(linked=true)` 解析为唯一 `node_id`（重名返回 `AMBIGUOUS_SESSION`）。
   - 调用 `get_session(session_id=<node_id>)`，获取当前的 `revision`（作为 `expected_revision`）、`node_status`、`active_run_id` 与 `operation_summaries`。
2. **前置忙碌检查与清理引导**：
   - 若存在 `active_run_id` 或未完成启动操作，或接下来的调用返回 `SESSION_BUSY`：
     1) 若有正在运行/启动/等待的 `run_id`，调用 `cancel_run(request_id=..., session_id=<node_id>, run_id=<active_run_id>, reason="Cancel before archiving session")` 并确认执行器已完全退出。
     2) 若队列中仍有 `queued` 消息，显式调用 `cancel_message` 逐一取消。
     3) 重新调用 `get_session(session_id=<node_id>)` 获取最新 `revision`。
3. **调用 `archive_session` 工具**：
   - 生成唯一 `request_id`（UUID），调用：
     ```json
     {
       "request_id": "<UUID>",
       "session_id": "<node_id>",
       "expected_revision": 1
     }
     ```
4. **反馈归档结果**：
   - 若成功（`node_status == "archived"`），向用户展示已归档节点的 `node_id`、`name`、最新 `revision`，并说明其历史报告、事件引用（`latest_report_ref`）与 worktree 路径均完整保留（可通过 `/side-sessions:tree --archived` 查看）。
   - 若返回 `REVISION_CONFLICT`，说明状态在归档期间发生变化，重新调用 `get_session` 核实状态后再决定是否重试。
