---
description: 经真人动作核验后批准待启动的子会话提案或降级的上下文候选快照（用法：/side-sessions:approve <proposal_id> 或 /side-sessions:approve context <operation_id> <snapshot_hash>）
---

# `/side-sessions:approve`

验证真实用户批准动作，完成对子会话提案（`proposal_id`）或上下文质量降级候选（`context <operation_id> <snapshot_hash>`）的可信授权。

## 支持的两种命令形式

1. **批准子会话提案**：
   ```text
   /side-sessions:approve <proposal_id>
   ```
   用于批准处于 `waiting_user` 状态的 `offer` 提议或 `own_initiative` 完整提案。
2. **批准上下文质量降级候选（R08）**：
   ```text
   /side-sessions:approve context <operation_id> <snapshot_hash>
   ```
   用于当 `fork`（`summary_copy`）因源历史映射受限降级为 `history_quality="brief_only"`、操作处于 `awaiting_context_acceptance` 时，显式授权该特定候选快照。

## Hook 同事务直接消费与模型职责（二期架构）

- **操作已由 `UserPromptSubmit` Hook 原子完成**：当真实用户输入 `/side-sessions:approve ...` 时，同步 `UserPromptSubmit` Hook 已在同一 SQLite `BEGIN IMMEDIATE` 事务内登记 `slash_command` 真人凭据、完成 `verify_and_consume_approval_in_txn` 消费与状态流转，并将结果注入本轮 `<system-reminder>`（`additionalContext`）。
- **模型严禁再次调用内部端口**：`approve_proposal` 与 `approve_context` 不作为公共 MCP 工具暴露。
  - 若 `<system-reminder>` 显示完整提案已批准并排入 `proposal_claim_jobs`（由后台 worker 异步领取启动），模型只需直接向用户汇报批准与排队启动结果，**严禁再调用 `approve_proposal` 或重复调用 `start_session`**。
  - 若 `<system-reminder>` 显示 `offer` 提议已流转为 `awaiting_brief`，模型随后调用 `start_session` 的 `ClaimOffer` 分支（传入 `proposal_id`、`prompt` 与 `>= 80` 码点的结构化 `background`）完成子会话启动。
  - 若 `<system-reminder>` 显示上下文候选已批准（`stage=ready_for_admission`），模型**必须使用原 `request_id` 与原业务参数重新调用原先暂停的 `start_session` 或 `hand_off_to_session`** 以完成槽位预留、工作区准备与子会话正式启动（严禁再尝试调用未公开的 `approve_context`）。
