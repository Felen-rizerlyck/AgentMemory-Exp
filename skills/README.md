# skills/ — 记忆板块 skill 的仓库内副本

本目录是 `security-log-case-memory` skill 的**项目内副本**，随本仓库统一管理（供日后并入独立安全检测 Agent）。

## 与 Hermes home 的关系

- **项目内副本（本目录）= 统一管理源**：改动在这里进行、随 git 走。
- **Hermes home 实时加载版**：`F:\HermesAgent\.hermes\skills\security\security-log-case-memory\`——这是会话里 `skill_view` 实际加载的镜像。

同步方向：改这里 → `cp -r skills/security-log-case-memory <Hermes home 对应路径>/` → 新会话生效。

## 目录结构

| 文件 | 作用 |
|---|---|
| `SKILL.md` | 主流程（先检索→判断→提取）与陷阱/要点 |
| `references/case-write-spec.md` | 案例写入严格规范（何时/哪个文件/格式/验证门禁） |
| `references/production-log-schema.md` | 生产结构化日志适配分析（接真实日志前先读） |

## 合并提醒

SKILL.md 内含绝对路径 `F:\AI_Learning\AgentMemory`（检索/落盘命令、文件路径）。并入独立安全检测 Agent 时需把该绝对路径替换为目标工作目录。
