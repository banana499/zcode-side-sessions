---
description: 取消并关闭尚未启动的子会话提案（用法：/side-sessions:dismiss <proposal_id>）
---

# `/side-sessions:dismiss <proposal_id>`

在可信调用方管理范围内取消并关闭指定的未启动子会话提案（`proposal_id`）。

## 参数说明

- `<proposal_id>`（必填，UUID）：待取消的提案 ID（处于 `waiting_user`、`awaiting_brief` 或 `approved` 状态）。

## Hook 直接拦截与模型职责

1. **优先读取 `UserPromptSubmit` Hook 回执**：
   - 当真实用户输入 `/side-sessions:dismiss <proposal_id>` 时，`UserPromptSubmit` Hook 已直接在当前进程完成提案取消并将 `[side-sessions:dismiss]` 结果注入 `<system-reminder>`（`additionalContext`）。
   - 若 `<system-reminder>` 已包含 `[side-sessions:dismiss]` 成功或终态回执，模型**只需读取该回执向用户汇报结果，无需也不得再次调用 `dismiss_task`**。
2. **仅当未传入 `<proposal_id>` 或需辅助查询时**：
   - 若用户未提供 `<proposal_id>`，可通过 `list_sessions(linked=true)` 列出当前待处理提案并提示用法 `/side-sessions:dismiss <proposal_id>`。
   - 若提案已启动（`ALREADY_STARTED` / `SPAWN_IN_FLIGHT`），告知用户 `dismiss` 不会杀死运行中的子会话；如需终止正在运行的回合，请使用 `/side-sessions:cancel run <run_id>`。
