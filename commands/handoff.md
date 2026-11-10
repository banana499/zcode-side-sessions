---
description: 将当前已登记长任务的未完成计划（remaining_plan）安全交接给独立子会话执行（用法：/side-sessions:handoff <task_id>）
---

# `/side-sessions:handoff <task_id>`

将当前会话持有的已登记任务（`task_id`）及其未完成计划（`remaining_plan`）通过两阶段所有权转移交接给独立子会话，使当前父会话能够安全释放出来处理用户的新诉求。

## 参数说明

- `<task_id>`（必填，UUID）：已通过 `register_task` 登记且当前由本会话节点持有的权威任务 ID。
- **前置门禁**：
  - 严禁凭空编造未登记的 UUID 冒充 `task_id`。若未提供 `<task_id>` 或不确定当前任务 ID，先调用 `get_current_task()` 或 `list_tasks()` 查询；若返回 `TASK_UNBOUND`，必须先明确告知用户当前无已绑定任务，不得强行交接。
  - 源历史截点（`SourceAnchor`）由实际源会话 owner 根据 `tasks.last_stable_anchor` 与触发边界自动捕获（排除新用户诉求与未完成工具调用），不接受模型手动传入源 SID 或伪造历史锚点。

## 执行步骤

1. **读取并核验任务事实（`get_task`）**：
   - 调用 `get_task(task_id=<task_id>)`。
   - 核对返回的 `owner_node_id` 等于当前会话节点，`state == "active"`，并记录当前的 `task_revision`、`title`、`remaining_plan`、`task_kind` 与 `scope`。
   - 确认 `title` 与 `remaining_plan` 去除首尾空白后均非空（若 `remaining_plan` 需要结合当前最新稳定进展更新，先整理清晰完整的非空剩余计划）。
2. **确定工作区与上下文策略**：
   - 根据 `task_kind` 严格匹配工作区：
     - `task_kind == "read_only"` -> `use_worktree = false`（`Workspace="inherit"`）
     - `task_kind == "write_code"` -> `use_worktree = true`（`Workspace="branch"`，在源 checkout 外的 `worktrees_home` 创建独立 Git worktree）
   - `context` 固定为 `"fork"`；由于当前父会话处于活动回合或跨目录创建 worktree，宿主不支持 `native_fork`（会返回 `UNSUPPORTED_LIVE_FORK` 或 `UNSUPPORTED_CONTEXT_WORKSPACE`），默认使用经批准的 `context_strategy="summary_copy"`。
3. **发起两阶段交接（`hand_off_to_session`）**：
   - 生成唯一 `request_id`（UUID）与 `transfer_id`（UUID），调用：
     ```json
     {
       "request_id": "<UUID>",
       "transfer_id": "<UUID>",
       "task_id": "<task_id>",
       "title": "<非空标题>",
       "remaining_plan": "<非空剩余计划>",
       "task_kind": "read_only | write_code",
       "use_worktree": true,
       "context": "fork",
       "context_strategy": "summary_copy",
       "expected_task_revision": 1
     }
     ```
4. **严格按返回状态分支处理（严禁虚报状态）**：
   - **分支 A：返回 `CONTEXT_QUALITY_APPROVAL_REQUIRED` / `status="awaiting_context_acceptance"`（历史质量降级为 `brief_only`）**：
     - 此时**尚未占槽、尚未创建 worktree/子会话、源任务也未暂停或转移**。
     - 向用户清晰展示返回的 `operation_id`、`snapshot_hash`、`brief_hash`、`history_quality="brief_only"`、降级原因及 `manifest_ref`。
     - 指引用户核对后执行 `/side-sessions:approve context <operation_id> <snapshot_hash>` 进行真人批准；严禁声称任务已交接或已排队。
   - **分支 B：返回 `CAPACITY_EXCEEDED`（父节点 4 个并发执行槽已满）**：
     - 明确告知用户当前直接父节点的 4 个并发槽位已满，交接被立即拒绝。
     - 说明源任务 `owner_node_id`、`state` 与 `task_revision` 均保持原状，未创建任何 transfer、dispatch member、inbox 消息或 worktree；**严禁向用户声称“已进入等待容量队列”或“源任务已暂停”**。
   - **分支 C：返回 `HANDOFF_GUARD_UNAVAILABLE` / `HANDOFF_SCOPE_UNSUPPORTED` / `DIRTY_SOURCE`**：
     - 如实向用户报告宿主任务屏障（`supports_task_guard`）不可用、外部作用域不支持重定位或源 Git 仓库存在未提交改动，源任务保持原状。
   - **分支 D：获槽准入并完成所有权转移（`transfer_preparing` -> `transferring` -> `committed`）**：
     - 展示分配的 `operation_id`、`transfer_id`、目标子会话 `node_id` / `runtime_session_id`、工作区分支及新的 `task_revision`。
     - 一旦任务进入保护/已提交转移，**当前父会话立即停止对原任务冻结作用域（`scope`）的一切写操作或继续执行动作**，转而处理用户的新诉求。
