# data/batches/ — 批次留档与参考样例

每个**被入库过**的批次在此留档，用途有两个：

1. `scripts/derive_action_sources.py` 的 `BATCH_EVIDENCE`（案例 `action_sources` 的证据来源）——**不要改名或删除**，改了会让来源标注回退到层集合推断；
2. 人工核对 / 复现 / 当作参考样例。

| 文件 | 批次 | 对应案例 | 说明 |
|---|---|---|---|
| `CASE-029_ProxyLogon_原样本.txt` | 2026-10-14 08:12~08:31（8 行 / 5 源 / 24 分钟） | CASE-029 | **参考样例**：ProxyLogon 风格完整链 —— SSRF 入口(X-BEResource) → IIS 工作进程执行(w3wp→cmd.exe) → ASPX webshell(aspnet_client) → 提权(PrintSpoofer/SeImpersonate) → 持久化(sc create 服务) → DNS TXT 长标签外传 |
| `deploy_test_2026-10-14.txt` | 部署场景测试批（12 行） | CASE-023 ~ CASE-028 | 部署测试批留档（原 `data/incoming_logs.txt` 内容，2026-10-15 归档，避免被下一批覆盖后来源推导失效） |

> 新批次先写 `data/incoming_logs.txt` 走流程；**判定为入库后**再复制到本目录（命名 `<批次日期>_<主题>.txt`），并在 `BATCH_EVIDENCE` 里登记「本目录路径 + 该批 log_id → 案例」。

## 参考样例怎么用（CASE-029）

```bash
# ① 链级检索（判定单元）
python src/retrieve.py --chain "data/batches/CASE-029_ProxyLogon_原样本.txt"
#    预期：1 条候选链（8 行，waf→web→hids→rasp→dns；entity/高）
#         [链] [CASE-029] 完整匹配 6/6（强）
#         ●1.X-BEResource[waf/web] ●2.w3wp→cmd[hids] ●3.aspnet_client ASPX[web/rasp]
#         ●4.PrintSpoofer[hids] ●5.sc create[hids] ●6.DNS TXT 外传[dns]

# ② 行级分诊（每行都是弱档前缀/中段，只作提示）
python src/retrieve.py --batch "data/batches/CASE-029_ProxyLogon_原样本.txt"
```

- 案例本体在 `data/memory_store.json` 的 `CASE-029`（含 `action_sequence` / `action_sources` / 指标 / 推理）。
- 该案例的写入过程（五处写入 + 顺序 + 门禁）见 skill `security-log-case-memory` 的 `references/case-write-spec.md`；
  运行流程见同 skill 的 `references/runtime-playbook.md`。
