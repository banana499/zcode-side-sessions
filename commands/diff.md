---
description: 只读预览 write_code 子会话分支 worktree 的代码变更、冲突预检与合并资格（用法：/side-sessions:diff <session>）
---

# `/side-sessions:diff <session>`

调用只读工具 `diff_worktree` 查看指定 `write_code` 子会话独立分支 worktree 相对于 `base_commit` 的变更摘要、补丁预览与绑定完整上下文的 `preview_hash`。

## 参数说明

- `<session>`（必填）：子会话短名称（`name`）或 `node_id`（UUID）。

## 执行步骤

1. 调用只读 MCP 工具 `diff_worktree(session_id="<session>")`。
2. 向用户清晰展示：
   - 子会话名称、`node_id`、分支名 `branch`、`base_commit` 与当前 `child_tip`（领先提交数 `commits_ahead`）；
   - 父仓库当前分支 `parent_full_ref` 与 `parent_head`；
   - 变更文件清单 `changed_files` 与补丁预览 `patch`；
   - 合并资格 `merge_eligible`（若为 `false`，说明阻断原因 `merge_block_reason`，如 `BASELINE_UNAVAILABLE`、`WORKTREE_DIRTY`、`SESSION_BUSY` 等）；
   - 64 位十六进制 `preview_hash`，并给出可直接复制执行的受控合并命令：
     ```text
     /side-sessions:merge <session> <preview_hash> [ff-only|merge|squash] [--cleanup]
     ```
