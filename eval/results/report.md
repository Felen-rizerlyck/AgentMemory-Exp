# 检索评测报告（DRAFT）

- 查询数: 95（分组: A-archive=33, A-constructed=5, B-must_hit=30, B-may_degrade=9, B-nl=9, C-negative=9）
- 案例库: 22 案例 · 关系矩阵: 231 对（DRAFT — 第二轮扩充：22 案例 / 231 对（旧 36 对沿用首轮草稿；本轮新增 195 对为机械预筛+初步裁定））
- 配置: 入口 C0/C1/C2；扩展 C3(全边)/C4(跨簇: shares_infra+chain_sibling+same_phase)/C5(簇内: same_technique+same_family+shares_payload) × 门槛 甲(≥6)/乙(≥4)
- C2 自检: 与 retrieve.score_case 比对 2090 对，差异 0

## 表1 入口质量（分组合计）

| 配置 | 分组 | n | Hit@1 | Hit@3 | MRR | 强命中率(≥6) | 噪声/查询 | misleading |
|---|---|---|---|---|---|---|---|---|
| C0 | A-archive | 33 | 85% | 88% | 0.86 | 55% | 0.12 | 0 |
| C0 | A-constructed | 5 | 100% | 100% | 1.00 | 100% | 0.20 | 0 |
| C0 | B-must_hit | 30 | 70% | 73% | 0.72 | 57% | 0.17 | 0 |
| C0 | B-may_degrade | 9 | 100% | 100% | 1.00 | 78% | 0.22 | 0 |
| C0 | B-nl | 9 | 100% | 100% | 1.00 | 100% | 0.44 | 0 |
| C1 | A-archive | 33 | 100% | 100% | 1.00 | 97% | 0.30 | 0 |
| C1 | A-constructed | 5 | 100% | 100% | 1.00 | 100% | 0.20 | 0 |
| C1 | B-must_hit | 30 | 100% | 100% | 1.00 | 83% | 0.33 | 0 |
| C1 | B-may_degrade | 9 | 100% | 100% | 1.00 | 100% | 0.33 | 0 |
| C1 | B-nl | 9 | 100% | 100% | 1.00 | 100% | 0.44 | 0 |
| C2 | A-archive | 33 | 100% | 100% | 1.00 | 100% | 0.33 | 0 |
| C2 | A-constructed | 5 | 100% | 100% | 1.00 | 100% | 0.20 | 0 |
| C2 | B-must_hit | 30 | 100% | 100% | 1.00 | 100% | 0.37 | 0 |
| C2 | B-may_degrade | 9 | 89% | 100% | 0.94 | 100% | 0.33 | 0 |
| C2 | B-nl | 9 | 100% | 100% | 1.00 | 100% | 0.44 | 0 |

负样本（C-negative）:  | 配置 | n | 空返回率 | 无中强命中率 | misleading | 噪声/查询 |
|---|---|---|---|---|---|
| C0 | 9 | 78% | 100% | 0 | 0.33 |
| C1 | 9 | 78% | 100% | 0 | 0.33 |
| C2 | 9 | 78% | 100% | 0 | 0.33 |

## 表2 扩展指标（C2 之上）

| 配置 | 门槛 | 新发现(helpful) | 新增噪声 | 新增误导 | CR B→E | EP(micro) | 候选成本 B̄→Ē | 负样本触发扩展 |
|---|---|---|---|---|---|---|---|---|
| C3 | 甲 | 110 | 37 | 0 | 69/179→179/179 | 75% | 2.2→3.9 | 0/9 |
| C3 | 乙 | 110 | 48 | 0 | 69/179→179/179 | 70% | 2.2→4.0 | 0/9 |
| C4 | 甲 | 26 | 0 | 0 | 69/179→95/179 | 100% | 2.2→2.5 | 0/9 |
| C4 | 乙 | 26 | 2 | 0 | 69/179→95/179 | 93% | 2.2→2.5 | 0/9 |
| C5 | 甲 | 92 | 37 | 0 | 69/179→161/179 | 71% | 2.2→3.7 | 0/9 |
| C5 | 乙 | 92 | 46 | 0 | 69/179→161/179 | 67% | 2.2→3.8 | 0/9 |

> 注: 本阶段扩展边来自 gold 人工直连，CR(E) 为上界（按构造≈捞回 gold 邻居）；机械推导版（Phase 2）精度将低于此。CR(B)→CR(E) 的差与『新发现』列即扩展的上下文增益。

## 表3 预注册判据核对（自动初判，人工终审）

- C3@甲: 判据1 新发现:噪声≥2:1 → 达标（110:37）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）
- C3@乙: 判据1 新发现:噪声≥2:1 → 达标（110:48）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）
- C4@甲: 判据1 新发现:噪声≥2:1 → 达标（26:0）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）
- C4@乙: 判据1 新发现:噪声≥2:1 → 达标（26:2）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）
- C5@甲: 判据1 新发现:噪声≥2:1 → 达标（92:37）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）
- C5@乙: 判据1 新发现:噪声≥2:1 → 达标（92:46）; 判据2 误导=0 → 达标（0）; 判据3 负样本零扩展≥90% → 达标（0/9）

## 附录A 扩展新发现样例

- C3@甲: Q-A-01→CASE-004+CASE-007; Q-A-03→CASE-016+CASE-018; Q-A-04→CASE-016; Q-A-05→CASE-001+CASE-007; Q-A-10→CASE-001+CASE-007
- C3@乙: Q-A-01→CASE-004+CASE-007; Q-A-03→CASE-016+CASE-018; Q-A-04→CASE-016; Q-A-05→CASE-001+CASE-007; Q-A-10→CASE-001+CASE-007
- C4@甲: Q-A-01→CASE-004+CASE-007; Q-A-05→CASE-001+CASE-007; Q-A-10→CASE-001+CASE-007; Q-S-01B→CASE-004+CASE-007; Q-S-07→CASE-001+CASE-004
- C4@乙: Q-A-01→CASE-004+CASE-007; Q-A-05→CASE-001+CASE-007; Q-A-10→CASE-001+CASE-007; Q-S-01B→CASE-004+CASE-007; Q-S-07→CASE-001+CASE-004
- C5@甲: Q-A-01→CASE-004; Q-A-03→CASE-016+CASE-018; Q-A-04→CASE-016; Q-A-05→CASE-001; Q-A-10→CASE-001
- C5@乙: Q-A-01→CASE-004; Q-A-03→CASE-016+CASE-018; Q-A-04→CASE-016; Q-A-05→CASE-001; Q-A-10→CASE-001

## 附录B 待复核的 gold 对（review=true）

- CASE-001 ↔ CASE-007 [helpful] same_phase: 同为 Windows 主机侧横向移动（WMIC 远程执行 vs SMB 管理共享），工具链对照价值
- CASE-004 ↔ CASE-007 [helpful] same_phase: 同为横向移动阶段（SSH 密钥 vs SMB 共享）；目的相同、机制不同，作上下文对照
- CASE-003 ↔ CASE-006 [weak] same_technique: 同 T1190，但手法栈不同（Node LFI 链 vs Java 反序列化）
- CASE-003 ↔ CASE-009 [weak] same_technique: 同 T1190 + 同为 WAF/RASP 双层；LFI 链 vs 登录认证攻击
- CASE-005 ↔ CASE-008 [weak] same_technique: 同为 Web 注入→命令执行（T1059.004 vs T1059.006 子技术不同）
- CASE-003 ↔ CASE-001 [weak] chain_sibling: PAT-001：Web 告警→约90s 后主机横向的时序伴生观察；按『独立事件』准则暂不建立关联
- CASE-003 ↔ CASE-004 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-003 ↔ CASE-007 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-005 ↔ CASE-001 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-005 ↔ CASE-004 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-005 ↔ CASE-007 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-006 ↔ CASE-001 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-006 ↔ CASE-004 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-006 ↔ CASE-007 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-008 ↔ CASE-001 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-008 ↔ CASE-004 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-008 ↔ CASE-007 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-009 ↔ CASE-001 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-009 ↔ CASE-004 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-009 ↔ CASE-007 [weak] chain_sibling: PAT-001 时序伴生候选；按『独立事件』准则暂不建立关联
- CASE-001 ↔ CASE-021 [weak] same_phase: 同为持久化（Windows 后门账户 vs Linux rc.local），系统与机制不同
- CASE-002 ↔ CASE-019 [weak] : 同经 DNS 通道（DGA C2 信标 / 外传隧道），机制不同；019 外送域含 8 位 hex 前缀形态（与 DGA 形状部分重叠）
- CASE-003 ↔ CASE-016 [helpful] same_technique+shares_payload: 共享 `cache_key=../../../tmp/<hex>` 穿越写法与 `smuggle=GET / HTTP/1.1` 标记（003 的 05-01 观测 / 016）
- CASE-003 ↔ CASE-018 [helpful] same_technique+shares_payload: 均以云元数据段（169.254.169.254）为读取目标：003 参数型 SSRF / 018 XXE 实体——云凭据窃取同类
- CASE-005 ↔ CASE-022 [helpful] same_technique+same_family: 同 T1190+T1059.004；均 Web 命令注入伴随 MSSQL 命令探针（xp_cmdshell / xp_dirtree）混投
- CASE-006 ↔ CASE-010 [helpful] same_technique+shares_payload: 共享 `cmd=id` 命令探针（010 请求含 &cmd=id 与 ShellSession 句柄）；同 T1190+T1059.004
- CASE-006 ↔ CASE-012 [weak] : 同为不安全反序列化致 RCE，语言/载荷机制不同（Java 流 vs PHP phar 上传）
- CASE-008 ↔ CASE-013 [helpful] same_technique+same_family: 表达式注入致命令执行：Jinja2 对象链 / SpEL routing-expression
- CASE-008 ↔ CASE-020 [helpful] same_technique+same_family: 表达式/脚本注入致命令执行：Jinja2 对象链 / Groovy .execute()
- CASE-009 ↔ CASE-015 [helpful] same_technique+same_family: SQL 注入类：009 认证绕过 / 015 UNION 窃取凭据表
- CASE-010 ↔ CASE-013 [helpful] same_technique+same_family: Java 表达式引擎类（MVEL 句柄 / SpEL）在 Web 参数中被执行
- CASE-010 ↔ CASE-016 [helpful] same_technique+shares_payload: 共享 `cmd=id` 探针（010 含 &cmd=id）
- CASE-010 ↔ CASE-022 [helpful] same_technique+shares_payload: 共享 `cmd=id` 探针
- CASE-013 ↔ CASE-020 [helpful] same_technique+same_family: 脚本/表达式引擎注入：SpEL / Groovy，引擎内执行命令
- CASE-014 ↔ CASE-015 [helpful] same_technique+shares_payload: 共享 `cmd_inject=#!//bin/bash` 标记
- CASE-014 ↔ CASE-021 [helpful] same_phase: 同为持久化阶段（cron 写任务 vs rc.local 启动脚本）——机制不同、目的同类
- CASE-015 ↔ CASE-019 [weak] : 同涉凭据获取（DB 凭据 UNION 导出 / 主机 /etc/shadow 外传），平台与机制不同
- CASE-016 ↔ CASE-018 [helpful] same_technique+shares_payload: 共享 `smuggle=GET / HTTP/1.1` 走私形态标记

---
*注：本报告为初版草稿；gold 矩阵与 qrels 复核后重跑 `python eval/run_eval.py` 即更新。*