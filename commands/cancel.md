---
description: 取消子会话正在运行的执行回合（run）或尚未认领的排队消息（message）（用法：/side-sessions:cancel run <run_id> 或 /side-sessions:cancel message <message_id>）
---

# `/side-sessions:cancel`

对受控子会话执行精确的回合终止（`cancel_run`）或排队消息撤回（`cancel_message`），并严格按真实退出确认反馈状态。

## 支持的两种命令形式

1. **终止正在启动/运行/等待输入的执行回合**：
   ```text
   /side-sessions:cancel run <run_id> [reason]
   ```
   对应调用 `cancel_run(request_id, session_id, run_id, reason)`。
2. **取消尚未被 worker 认领的排队消息**：
   ```text
   /side-sessions:cancel message <message_id> [reason]
   ```
   对应调用 `cancel_message(request_id, session_id, message_id, reason)`。

## 核心安全与状态报告规范（R04）

- **未确认退出前严禁声称槽位已释放**：
  - `cancel_run` 发起后，回合先进入 `stopping` 状态（此时仍占用父节点的执行槽位与 `session-<node_id>.lock` 运行锁）。
  - 只有当当前 owner 走完协议停止（`session/stop` 等待 5 秒 -> 核对进程身份后 `SIGTERM` 等待 5 秒 -> `SIGKILL` 等待 5 秒）并取得 `ExitReceipt.exit_confirmed == true` 完成收尾事务后，状态才变为 `cancelled` 且槽位真正释放。
- **区分三种取消状态反馈**：
  - `stopping`：停止指令已入队或正在终止进程树，槽位尚未释放。
  - `cancelled` / `already_exited`：执行器已确认退出（或消息在未启动前被证明取消 `not_started_proven`），槽位已释放。
  - `cancel_unknown` / `CANCEL_OWNER_UNAVAILABLE`：无法验证进程归属或外部 GUI owner 连接不可用，进入 `reconciliation`，保留槽位占用，绝不盲目强杀未知进程或谎报已取消。

## 执行步骤

### 模式一：`/side-sessions:cancel run <run_id> [reason]`

1. **定位会话与回合**：
   - 通过 `list_sessions(linked=true)` 或 `get_session(session_id=...)` 确认 `<run_id>` 所属的 `session_id`（`node_id`）。
   - 确保 `reason` 非空（若用户未提供原因，使用默认值如 `"User requested run cancellation via /side-sessions:cancel"`）。
2. **调用 `cancel_run` 工具**：
   - 生成唯一 `request_id`（UUID），调用：
     ```json
     {
       "request_id": "<UUID>",
       "session_id": "<node_id>",
       "run_id": "<run_id>",
       "reason": "<非空取消原因>"
     }
     ```
3. **查询控制回执并如实汇报（`get_control` / `get_session`）**：
   - 根据返回的 `ControlResult`（及后续 `get_control(control_id=...)`）向用户明确区分：
     - 若状态为 `stopping`：说明取消请求已由 owner 接收并正在停止进程，**当前槽位仍被保留，尚未释放**。
     - 若状态为 `applied` / `already_exited` 且会话回合已确认退出：说明回合已 `cancelled`（若此前已有 `final` 报告则保留原 `final` 不覆盖），槽位已释放。
     - 若状态为 `unknown` 或错误码 `CANCEL_OWNER_UNAVAILABLE`：说明外部执行器状态未明，会话保持保护/待核查状态，槽位未释放。

### 模式二：`/side-sessions:cancel message <message_id> [reason]`

1. **定位目标消息与会话**：
   - 确认 `<message_id>` 所属的 `session_id`（`node_id`）及非空 `reason`。
2. **调用 `cancel_message` 工具**：
   - 生成唯一 `request_id`（UUID），调用：
     ```json
     {
       "request_id": "<UUID>",
       "session_id": "<node_id>",
       "message_id": "<message_id>",
       "reason": "<非空取消原因>"
     }
     ```
3. **处理竞争裁决结果**：
   - **未认领直接取消成功**：若消息仍处于 `queued` 未被 worker 认领，事务原子将其标为 `cancelled`，对应派发组成员记为 `terminal`（`exit_confirmed="not_started_proven"`），不消耗宿主回合。
   - **消息已被认领或正在运行（返回 `MESSAGE_IN_FLIGHT`）**：
     - 明确告知用户该消息已被 worker 认领并分配了内部 `run_id`，无法作为静态排队消息撤回。
     - 展示错误详情中返回的 `run_id`，并引导或直接执行 `/side-sessions:cancel run <run_id>` 终止该运行回合。
