---
description: 经真人动作核验后，独立安全清理空闲干净的子会话分支 worktree 并归档子会话（用法：/side-sessions:cleanup <session>）
---

# `/side-sessions:cleanup <session>`

经真实用户斜杠命令授权，独立清理空闲且工作区干净的 `write_code` 子会话分支 worktree 目录，并将该子会话节点归档为 `archived`。

## 参数说明

- `<session>`（必填，仅接受 1 个参数）：目标子会话的短名称（`name`）、逻辑 `node_id`（UUID）或 `runtime_session_id`。若参数个数不为 1，将显式返回 `INVALID_REQUEST`。

## 安全核验与分支保留语义

- **脏目录拒清保护（`retained_dirty`）**：后台 Worker 在 `session_lock -> repo_merge_lock` 下调用 `verify_owned_post_run` 核查磁盘状态。若子 worktree 存在未提交改动、未跟踪文件或被忽略的用户文件，拒绝删除磁盘目录并将 `worktrees.state` 置为 `retained_dirty`，完整保留现场供用户检查。
- **干净清理与无损分支保留**：当子 worktree 100% 干净时，安全移除磁盘 worktree 目录并将子节点置为 `archived`、`worktrees.state = 'cleaned'`：
  - 若该分支已完成 `ff-only` 或 `merge` 合并且无额外提交，安全执行 `git branch -d` 清理分支引用；
  - 若该分支**尚未合并但存在新提交**，或采用 `squash` 模式合并，仅移除磁盘 worktree 目录，**无损保留 `side/<hex>` Git 分支引用**，确保已提交代码绝不丢失。

## Hook 登记与主代理职责红线

- 当真实用户输入 `/side-sessions:cleanup <session>` 时，`UserPromptSubmit` Hook 会在同事务内完成参数核验、消费真人凭据、写入 `worktree_jobs(kind='cleanup', state='queued')` 并通过 `WorkerKicker` 唤醒后台 Worker 异步执行。
- 内部清理实现（`cleanup_worktree` / `enqueue_cleanup_worktree_job`）**不作为公共 MCP 工具暴露**；主代理只需读取 `<system-reminder>` / `additionalContext` 中的 `[side-sessions:cleanup]` 回执向用户汇报入队或执行结果（可配合只读 `get_session` / `list_sessions` 查询状态），严禁尝试调用任何内部未暴露端口。
