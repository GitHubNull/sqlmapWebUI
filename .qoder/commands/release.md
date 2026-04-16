---
description: 发布新版本 - 同步版本号、更新变更日志、触发 GitHub Actions 自动构建
---

## Overview
执行完整的版本发布流程：同步所有组件版本号（后端、Burp 插件）→ 更新变更日志 → 创建 Git Tag → 推送触发 GitHub Actions 自动构建发布。

## Pre-flight Checks
- [ ] 当前分支为 `master`（本项目默认分支）
- [ ] 工作区干净（`git status` 无未提交的垃圾文件）
- [ ] 最近的 commit 是稳定的
- [ ] 已确定语义化版本号（如 `1.8.34`）

## Execution Steps

### 1. 确定版本号
```bash
# 获取最新 tag，提取版本号
git describe --tags --abbrev=0 2>/dev/null || echo "无历史 tag"

# 查看待发布的提交
git log --oneline -10
```

**版本号规则：**
- 格式：`数字.数字.数字`（如 `1.8.34`，不含 `v` 前缀）
- 必须大于当前最新版本
- 语义化：破坏性变更→主版本，新功能→次版本，修复→修订号

### 2. 更新 README 变更日志

首先查看自上次发布以来的提交记录，确定变更内容：
```bash
# 查看自上次 tag 以来的提交
git log $(git describe --tags --abbrev=0 2>/dev/null)..HEAD --oneline --no-merges
```

在 `README.md` 和 `README_EN.md` 的变更日志章节顶部插入新版本记录：

```markdown
### [v1.8.34] - 2026-02-27

#### ✨ 新增
- <新功能描述>

#### 🐛 修复
- <问题修复>

#### 📝 其他
- <其他变更>
```

> **注意**：中英文 README 的变更日志必须同步更新。

### 3. 同步所有版本号（共 7 处）

#### 3.1 后端版本（1 处）
| 文件 | 位置 | 格式 |
|------|------|------|
| `src/backEnd/config.py` | 第 7 行 | `VERSION = "1.8.34"` |

#### 3.2 Burp 插件版本（6 处）
| 文件 | 位置 | 格式 |
|------|------|------|
| `src/burpEx/legacy-api/pom.xml` | 第 9 行 | `<version>1.8.34</version>` |
| `src/burpEx/montoya-api/pom.xml` | 第 9 行 | `<version>1.8.34</version>` |
| `src/burpEx/legacy-api/.../BurpExtender.java` | 第 46 行 | `EXTENSION_VERSION = "1.8.34"` |
| `src/burpEx/legacy-api/.../AboutDialog.java` | 第 14 行 | `VERSION = "1.8.34"` |
| `src/burpEx/montoya-api/.../SqlmapWebUIExtension.java` | 第 22 行 | `EXTENSION_VERSION = "1.8.34"` |
| `src/burpEx/montoya-api/.../AboutDialog.java` | 第 14 行 | `VERSION = "1.8.34"` |

**批量替换命令：**
```bash
# [PowerShell] 查看当前版本（假设旧版本为 1.8.33）
Select-String -Path "src/backEnd/config.py","src/burpEx/*/pom.xml","src/burpEx/*/src/main/java/com/sqlmapwebui/burp/*.java","src/burpEx/*/src/main/java/com/sqlmapwebui/burp/dialogs/AboutDialog.java" -Pattern "1.8.33"

# [Bash] 查看当前版本
grep -rn "1.8.33" src/backEnd/config.py src/burpEx/*/pom.xml src/burpEx/*/src/main/java/com/sqlmapwebui/burp/*.java src/burpEx/*/src/main/java/com/sqlmapwebui/burp/dialogs/AboutDialog.java
```

```bash
# [PowerShell] 批量替换为新版本
Get-ChildItem -Path src/backEnd/config.py,src/burpEx -Recurse -Include config.py,pom.xml,*.java | ForEach-Object {
    (Get-Content $_.FullName) -replace '1.8.33', '1.8.34' | Set-Content $_.FullName
}

# [Bash] 批量替换为新版本
find src/backEnd -name "config.py" -exec sed -i 's/1.8.33/1.8.34/g' {} \;
find src/burpEx -name "pom.xml" -exec sed -i 's/1.8.33/1.8.34/g' {} \;
find src/burpEx -name "*.java" -exec sed -i 's/"1.8.33"/"1.8.34"/g' {} \;
```

**校验：**
```bash
# [PowerShell] 确认无遗漏
Select-String -Path "src/backEnd/config.py","src/burpEx" -Pattern "旧版本号" -Recurse

# [Bash] 确认无遗漏
grep -rn "旧版本号" src/backEnd/config.py src/burpEx/
```

**校验清单：**
- [ ] 7 处版本号已全部更新
- [ ] 版本号格式正确（不含 `v` 前缀）

### 4. 一次性提交所有版本发布变更

> **关键**：所有版本相关的修改（版本号 + 变更日志）必须在同一个 commit 中提交，不要拆分成多个 commit。

```bash
git add src/backEnd/config.py src/burpEx/ README.md README_EN.md
git commit -m "chore: release v1.8.34"
```

### 5. 创建 Tag 并推送

> **重要**：本项目使用 `release-v版本号` 格式的 Tag 触发 GitHub Actions

```bash
# 创建带注释的 tag（必须使用 release-v 前缀）
git tag -a release-v1.8.34 -m "Release v1.8.34

主要变更：
- <简要描述>

详见 README.md 变更日志"

# 推送 commit
git push origin master

# 推送 tag 触发自动发布
git push origin release-v1.8.34
```

### 6. 验证发布
- [ ] GitHub Actions 工作流已触发（查看 Actions 标签页）
- [ ] 等待构建完成（约 3-5 分钟）
- [ ] GitHub Releases 页面出现新版本
- [ ] 发布包完整：
  - `sqlmapwebui-1.8.34.zip`（后端+前端）
  - `sqlmap-webui-burp-montoya-1.8.34.jar`
  - `sqlmap-webui-burp-legacy-1.8.34.jar`
  - `vulnTestServer-1.8.34.zip`

## Error Recovery

**Tag 打错（未推送）：**
```bash
git tag -d release-v错误版本
# 修正后重新打 tag
```

**Tag 已推送需要回滚：**
```bash
git push --delete origin release-v错误版本
git tag -d release-v错误版本
# 修正后重新执行第 4 步
```

## Safety Warnings
⚠️ **Tag 格式必须正确**：
- 必须使用 `release-v数字.数字.数字` 格式（如 `release-v1.8.34`）
- 错误格式不会触发 Actions：`v1.8.34`、`1.8.34`、`release-1.8.34`

⚠️ **版本号格式区分**：
- 代码中版本号：不含 `v` 前缀（`1.8.34`）
- Git Tag 版本号：含 `release-v` 前缀（`release-v1.8.34`）
- README 变更日志：含 `v` 前缀（`v1.8.34`）

⚠️ **版本同步检查清单**：
- 后端 `config.py` 版本（1 处）
- Burp pom.xml 版本（2 处）
- Burp Java 常量版本（4 处）
- 共 7 处，漏更会导致版本显示不一致
