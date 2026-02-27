---
description: 智能代码提交 - 自动过滤垃圾文件，生成规范的语义化提交信息
---

## Overview
执行代码提交前的智能检查：过滤临时文件和日志 → 检查变更内容 → 生成符合 Conventional Commits 规范的提交信息。

> 如需正式发布版本，请使用 `/release` 命令

## Pre-flight Checks
- [ ] 有待提交的代码变更
- [ ] 已完成本地测试
- [ ] 工作区无垃圾文件

## Execution Steps

### 1. 检查变更状态
```bash
git status
```

**需要排除的垃圾文件：**
| 类型 | 文件模式 |
|------|---------|
| 日志/重定向 | `*.log`, `nul`, `*.out`, `*.err` |
| 截图 | `*.png`, `*.jpg`（除 `tmp/img/`、`doc/` 目录） |
| 临时文件 | `*.tmp`, `*.swp`, `.DS_Store`, `Thumbs.db` |
| 构建产物 | `target/`, `dist/`, `node_modules/`, `__pycache__/` |
| IDE 配置 | `.idea/workspace.xml`, `.vscode/` |
| 数据库 | `*.db`, `*.sqlite`（除示例数据） |

**处理垃圾文件：**
```powershell
# [PowerShell] 查看未跟踪文件
git status --porcelain | Select-String "^\?\?"

# [Bash] 查看未跟踪文件
git status --porcelain | grep "^??"
```

```bash
# 从暂存区移除垃圾文件（通用）
git reset HEAD <垃圾文件>

# [PowerShell] 添加到 .gitignore
Add-Content .gitignore "*.log"

# [Bash] 添加到 .gitignore
echo "*.log" >> .gitignore
```

### 2. 暂存变更
```bash
# 添加指定文件
git add src/ README.md

# 或添加所有变更（确认无垃圾文件后）
git add .

# 查看暂存内容
git diff --cached --stat
```

### 3. 生成提交信息

**Conventional Commits 格式：**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type 类型：**
| Type | 说明 | 版本影响 |
|------|------|---------|
| `feat` | 新功能 | 次版本+1 |
| `fix` | Bug 修复 | 修订号+1 |
| `docs` | 文档更新 | 无 |
| `refactor` | 重构（无功能变化） | 无 |
| `perf` | 性能优化 | 无 |
| `test` | 测试相关 | 无 |
| `chore` | 构建/工具/依赖 | 无 |
| `style` | 代码格式（无逻辑变化） | 无 |

**Scope 范围（本项目）：**
- `backend` - 后端 Python 代码
- `frontend` - 前端 Vue 代码
- `burp` - Burp Suite 插件
- `vulnlab` - 靶场
- `api` - API 相关
- `ui` - 界面相关

**示例：**
```bash
# 新功能
git commit -m "feat(backend): 添加任务批量删除功能

- 新增 /api/tasks/batch-delete 接口
- 支持按状态过滤批量删除
- 添加确认弹窗防止误操作

Closes #123"

# Bug 修复
git commit -m "fix(frontend): 修复任务列表分页显示错误

修复当总数为 0 时分页器显示 NaN 的问题"

# 文档更新
git commit -m "docs: 更新 API 文档"

# 重构
git commit -m "refactor(api): 统一响应格式"

# 多模块变更
git commit -m "feat: 支持 Header 作用域配置

- backend: 新增 scope_matcher 模块
- frontend: 添加 ScopeConfigPanel 组件
- 支持协议、主机、端口、路径匹配"
```

### 4. 推送到远程
```bash
# 推送到 master 分支
git push origin master
```

## Post-commit

**后续操作建议：**
- 如需发布版本 → 执行 `/release` 命令
- 如需创建 PR → 在 GitHub 页面操作
- 如需回滚 → 见下方 Rollback

## Rollback

**撤销最近一次提交（保留代码）：**
```bash
git reset --soft HEAD~1
```

**撤销最近一次提交（丢弃代码）：**
```bash
git reset --hard HEAD~1
```

**修改最近一次提交信息：**
```bash
git commit --amend -m "新的提交信息"
```

## Safety Warnings

⚠️ **禁止提交：**
- `*.log`, `nul`, `*.out` - 日志/重定向文件
- `.env`, `*credentials*`, `*secret*` - 敏感信息
- `*.db` - 本地数据库（除示例数据）
- 大于 10MB 的二进制文件

⚠️ **提交前检查：**
```bash
# [PowerShell] 确认没有敏感文件
git diff --cached --name-only | Select-String -Pattern "\.env|secret|password|credential"

# [Bash] 确认没有敏感文件
git diff --cached --name-only | grep -E "\.env|secret|password|credential"
```
