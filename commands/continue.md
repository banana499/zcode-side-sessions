---
description: 显式恢复处于 paused 或 done 状态的子会话并发送跟进消息（用法：/side-sessions:continue <target> <message>）
---

# `/side-sessions:continue <target> <message>`

以 `resume_policy="explicit"` 显式恢复处于 `paused` 或 `done` 状态的已有子会话节点，并将跟进消息排入其原有 FIFO 队列中继续执行。

## 参数说明

- `<target>`（必填）：目标子会话的逻辑 `node_id`（UUID）或当前 family 内无歧义的安全短名称 `name`（`[a-z][a-z0-9-]{0,47}`）。
- `<message>`（必填）：发送给该子会话的下一回合跟进指令（去除首尾空白后不得为空）。

## 行为边界与约束

- **专用于 `paused` / `done` 节点的显式续接**：
  - 当子会话处于 `paused` 或 `done` 时，普通 `send_message_to_session(..., resume_policy="active_only")` 会被拒绝并返回 `SESSION_PAUSED` / `SESSION_DONE`。
  - `/side-sessions:continue` 通过 `resume_policy="explicit"` 在同一数据库事务中将节点状态从 `paused` / `done` 改回 `active`，将仍归属该子节点的 `primary_task_id` 从 `paused` / `done` 恢复为 `active` 并递增 `task_revision`，随后将该消息排入同一节点的持久化 FIFO 队列。
- **原会话复用铁律**：恢复执行时复用该节点原有的 `runtime_session_id` 与原有工作区（`inherit` 或 `branch` worktree），绝不创建新节点冒充续接。
- **禁止隐式恢复 `archived` 节点**：若目标节点已归档（`node_status == "archived"`），直接拒绝并返回错误，不进行隐式解档。
- **不替代 `waiting_input` 回复**：若目标节点当前处于 `waiting_input`（正在等待用户输入或权限确认），本命令的 FIFO 消息只会作为**下一回合**排队输入，不会解除当前回合等待；必须提示用户使用 `/side-sessions:respond <wait_id>`。

## 执行步骤

1. **解析并校验目标节点与消息**：
   - 确认 `<target>` 与非空 `<message>` 已提供。
   - 若 `<target>` 为短名称且在同 family 内存在多个同名节点，返回 `AMBIGUOUS_SESSION` 并列出候选 `node_id` 供用户明确指定，禁止自行猜测最近会话。
2. **调用 `send_message_to_session`（`resume_policy="explicit"`）**：
   - 生成唯一 `request_id`（UUID）与 `message_id`（UUID），调用：
     ```json
     {
       "request_id": "<UUID>",
       "message_id": "<UUID>",
       "session_id": "<target>",
       "message": "<message>",
       "resume_policy": "explicit"
     }
     ```
3. **处理返回结果**：
   - **成功入队（`status="queued"` 或 `"running"`）**：
     - 向用户展示目标节点的 `node_id`、`message_id`、队列序号 `seq` 及队列位置 `queue_position`。
     - 若返回包含 `wait_summaries`（表明节点当前正处于 `waiting_input`），额外提醒用户先通过 `/side-sessions:respond <wait_id>` 处理当前回合等待。
   - **任务所有权已转移（返回 `TASK_OWNER_CHANGED`）**：
     - 明确告知用户该节点原主任务的所有权已通过 handoff 转移给其他节点，不能在旧节点上重启该任务，并提示当前持有该任务的最新节点 ID。
   - **宿主恢复受限（返回 `RUNTIME_CONFIG_MISMATCH` / `WORKSPACE_MISMATCH` / `HOST_PARENT_MISMATCH` / `needs_rehydration`）**：
     - 如实报告原宿主记录或工作区校验不通过的原因，绝不静默新建会话顶替。
