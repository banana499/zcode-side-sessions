---
description: 查看并经真人动作核验后响应子会话当前的等待请求（用法：/side-sessions:respond <wait_id> [answer...]）
---

# `/side-sessions:respond <wait_id> [answer...]`

查询或经真人动作核验后响应处于 `waiting_input` 状态的子会话等待请求（`input` / `elicitation` / `permission`）。

## 支持的两种用法

1. **直接提交真人响应（由 `UserPromptSubmit` Hook 同事务自动补齐 `nonce` 并执行）**：
   ```text
   /side-sessions:respond <wait_id> <answer...>
   ```
   - 当用户同时提供 `<wait_id>` 与 `<answer...>` 时，`UserPromptSubmit` Hook 会在数据库事务内自动读取该等待的真实 `kind`、`nonce` 与 `options`，将 `<answer...>` 归一化为合法 `WaitResponse`，登记绑定 `(wait_id, nonce, response_hash)` 的真人凭据并完成 `respond_to_wait` 调用。
   - **模型只需读取 `<system-reminder>` 中的 `[side-sessions:respond]` 回执向用户回报结果，严禁再重复调用 `respond_to_wait`**。
2. **仅查看等待详情与候选项（只传 `<wait_id>`）**：
   ```text
   /side-sessions:respond <wait_id>
   ```
   - 当用户仅传入 `<wait_id>` 而未提供 `<answer...>` 时，调用只读工具 `list_waits` 查询并向用户展示该等待项的 `wait_id`、`node_id`、`kind`、`question`、`options`、`required_authority` 与到期时间，提示用户执行 `/side-sessions:respond <wait_id> <answer...>` 完成应答。

## 安全与授权边界（R04）

- `kind == "permission"` 或 `required_authority == "human"` 的等待必须经真实人类输入核验（`verify_and_consume_approval_in_txn`）；模型在对话中复述“同意授权”绝不构成批准凭据。
- 默认 `input` 与 `elicitation` 等待的 `required_authority` 为 `parent_agent_allowed`（除非宿主事件显式指定 `human`）。
