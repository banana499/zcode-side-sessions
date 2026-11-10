---
description: 经真人动作核验并比对 preview_hash 后，将子会话分支 worktree 零污染合并回父仓库（用法：/side-sessions:merge <session> <preview_hash> [ff-only|merge|squash] [--cleanup]）
---

# `/side-sessions:merge <session> <preview_hash> [ff-only|merge|squash] [--cleanup]`

经真实用户斜杠命令授权，将空闲、干净的 `write_code` 子会话分支 worktree 按指定模式合并回父仓库，并可选在合并成功后自动安全清理 worktree 并归档子会话。

## 参数说明

- `<session>`（必填）：子会话短名称（`name`）或 `node_id`。
- `<preview_hash>`（必填，64 位十六进制）：由 `/side-sessions:diff <session>` 生成的预览哈希（绑定父仓 `HEAD`、子仓 `HEAD`/tree 与补丁摘要）。
- `[ff-only|merge|squash]`（可选，默认 `merge`）：合并模式（底层统一通过 `git merge-tree --write-tree` + `git commit-tree` 在对象库预构建候选提交，再于父仓库执行零污染 `git merge --ff-only`）。
- `[--cleanup]`（可选）：合并成功后在同一锁内安全移除 worktree 并归档该子会话节点（`squash` 模式默认保留分支引用）。

## Hook 登记与后台 Worker 执行说明

- 当真实用户输入 `/side-sessions:merge ...` 时，`UserPromptSubmit` Hook 会在 `<50ms` 内完成参数校验、消费 `purpose="worktree_merge"` 真人凭据、写入 `worktree_jobs(state='queued')` 并唤醒后台 worker，同时通过 `<system-reminder>` 返回 `job_id`。
- `merge_worktree` 与 `cleanup_worktree` 不作为公共 MCP 工具暴露；模型只需读取 `<system-reminder>` 中的 `[side-sessions:merge]` 回执向用户报告合并任务已入队或已完成。
