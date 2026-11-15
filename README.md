# keyhound

> **Zero-dependency secret scanner for repos, pre-commit and CI.**
> 纯 Python 标准库实现的密钥/凭据扫描器，零依赖、克隆即可运行。

![CI](https://github.com/yuezihao85/keyhound/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

代码提交前把 API key、数据库密码、私钥、Token 挡在仓库外面。keyhound 用
**正则规则 + 香农熵启发式** 找泄露，用 **指纹 baseline** 管理存量，
输出 **SARIF 2.1.0** 直接喂给 GitHub Code Scanning。

---

## 为什么值得放一个在仓库里

- `pip install` 都不是必须的：`python keyhound-cli.py .` 就能扫。
- 不联网、不上传、不依赖第三方包，CI 里没有供应链风险。
- 报告**永远不打印密钥原文**（默认 `前4 + ************ + 后2`）。
- 指纹由 `规则 + 相对路径 + 密钥哈希` 生成，**行号变化不会让 baseline 失效**。

---

## 特性

| | |
|---|---|
| 21 条内置规则 | AWS / GitHub / GitLab / Slack / Stripe / GCP / npm / PyPI / SendGrid / Mailgun / Twilio / OpenAI / JWT / PEM 私钥 / 数据库连接串 |
| 熵检测 | Shannon 熵 + 字符类别混合检查，识别未收录的高熵赋值 |
| 三种输出 | `console`（人读）、`json`（脚本）、`sarif`（GitHub Code Scanning） |
| Baseline | 已知问题一键入库，只报新增泄露；支持 `--update-baseline` |
| `.gitignore` | 完整支持，且**嵌套 `.gitignore` 只作用于自己所在子树** |
| 白名单 | 值白名单 + 上下文白名单（`os.environ` / `keyhound:allow` / `nosec`） |
| 误报抑制 | 特定规则命中时自动丢弃重叠的通用规则结果 |
| 跳过二进制 | 扩展名 + NUL 字节双检查，默认跳过 2 MB 以上文件 |
| 兼容 | Python 3.7+ / Linux · macOS · Windows / 仅标准库 |

---

## 快速开始

```bash
git clone https://github.com/yuezihao85/keyhound.git
cd keyhound

# 零安装，直接扫当前仓库
python keyhound-cli.py .

# 或者装成命令
pip install .
keyhound .
```

生成配置模板和基线：

```bash
python keyhound-cli.py --init               # 写出 .keyhound.json
python keyhound-cli.py --list-rules         # 查看全部规则
python keyhound-cli.py --init-baseline .    # 把当前命中记为已知
```

扫描暂存区 diff（不落盘）：

```bash
git diff --cached | python keyhound-cli.py -
```

---

## 命令行参数

```
keyhound [OPTIONS] [PATH ...]
```

`PATH` 可以是文件或目录，默认 `.`；`-` 表示从 stdin 读取（不能与其它路径混用）。

### 输出

| 参数 | 说明 |
|---|---|
| `-f, --format` | `console`（默认）/ `json` / `sarif` |
| `-o, --output FILE` | 写文件而不是 stdout，自动创建父目录 |
| `--color auto\|always\|never` | 控制台配色；`NO_COLOR` 环境变量也会关闭 |
| `--show-suppressed` | 在控制台额外列出被 baseline 压掉的条目 |

### 策略

| 参数 | 说明 |
|---|---|
| `--fail-on low\|medium\|high\|critical` | 达到该严重级别才返回退出码 1（默认 `low`） |
| `--min-severity LEVEL` | 隐藏低于该级别的命中（默认 `low`） |
| `--baseline FILE` | 指定基线文件（默认自动找 `.keyhound-baseline.json`） |
| `--no-baseline` | 完全忽略基线 |
| `--init-baseline` | 把当前全部命中写成基线后退出 0 |
| `--update-baseline` | 把当前命中追加进已有基线后退出 0 |
| `--reason TEXT` | 写入基线条目的备注 |

### 过滤

| 参数 | 说明 |
|---|---|
| `--exclude GLOB` | 追加忽略规则，可重复 |
| `--include GLOB` | 只扫描匹配的相对路径，可重复 |
| `--disable-rule ID` | 停用某条规则，可重复 |
| `--no-gitignore` | 忽略所有 `.gitignore` 内容 |
| `--max-size BYTES` | 跳过更大的文件（默认 2097152） |
| `--min-entropy BITS` | 通用规则的熵阈值（默认 3.5，范围 0–8） |
| `--min-length N` | 通用规则的最小长度（默认 16） |

### 配置与杂项

| 参数 | 说明 |
|---|---|
| `-c, --config FILE` | 指定配置文件；文件不存在会以退出码 2 报错 |
| `--no-config` | 不读取任何配置文件 |
| `--init` | 写出默认 `.keyhound.json` 并退出 |
| `--list-rules` | 打印规则清单并退出 |
| `-V, --version` | 版本号 |

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 无活跃命中（或 `--init` / 基线命令成功） |
| `1` | 存在严重级别 ≥ `--fail-on` 的命中 |
| `2` | 参数错误、配置/基线读取失败、写入失败 |

---

## 配置 `.keyhound.json`

`--init` 生成的模板：

```json
{
  "exclude": ["*.min.js", "*.map", "*.lock", "*.pdf", "*.png", "*.jpg",
              "*.jpeg", "*.gif", "*.ico", "*.woff*", "*.zip", "*.gz", "*.pyc"],
  "include": [],
  "min_entropy": 3.5,
  "min_length": 16,
  "max_size_bytes": 2097152,
  "disabled_rules": [],
  "custom_rules": [],
  "allowlist": [],
  "use_gitignore": true,
  "fail_on": "low"
}
```

字段说明：

- `exclude` / `include`：相对扫描根目录的 glob；`include` 非空时只扫命中项。
- `disabled_rules`：规则 id 列表，等价于多次 `--disable-rule`。
- `custom_rules`：自定义规则数组，见下节。
- `allowlist`：正则数组。每条会同时匹配「密钥值」「完整命中文本」「命中前后 ±40 字符的上下文」。
  内置的上下文白名单已经包含 `os.environ`、`process.env`、`getenv`、`ENV[`、
  `System.getenv`、`keyhound:allow`、`nosec`，因此下面这种写法天然免报：

  ```python
  token = os.environ.get("DEPLOY_TOKEN")          # 环境变量引用，不是硬编码
  api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"  # keyhound:allow  ← 行内显式放行
  ```

- 命令行参数优先级高于配置文件。

### 自定义规则

```json
{
  "custom_rules": [
    {
      "id": "acme-internal-token",
      "description": "ACME 内部系统令牌",
      "severity": "high",
      "pattern": "\\bACME-[A-Z0-9]{12}\\b",
      "tags": ["internal"]
    },
    {
      "id": "legacy-db-password",
      "description": "旧版配置里的 db_pass",
      "severity": "critical",
      "pattern": "(?i)db_pass\\s*=\\s*[\"']?([A-Za-z0-9_\\-]{12,})",
      "secret_group": 1,
      "min_entropy": 3.0,
      "min_length": 12
    }
  ]
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `id` / `description` / `severity` / `pattern` | 必填 | `severity` ∈ `low/medium/high/critical` |
| `secret_group` | `0` | 捕获组编号，`0` 表示整个匹配；报告只对这个组脱敏/计算指纹 |
| `min_entropy` | `0.0` | 该组值的香农熵下限 |
| `min_length` | `0` | 该组值的最小长度 |
| `generic` | `false` | 标记为启发式规则；被更具体的规则覆盖时自动丢弃 |
| `safe_to_show` | `false` | 如 PEM 头这种非敏感文本，允许原样输出 |
| `tags` | `[]` | 透传到 JSON / SARIF 的 `tags` |

> 正则里如果用 `(?i)` 这类全局内联标志，请放在表达式最开头；keyhound 会自动把它
> 改写成作用域形式 `(?i:...)` 以便安全地与其它白名单表达式拼接。

---

## Baseline 工作流

指纹计算方式是：

```
sha256( rule_id + "\0" + posix_path + "\0" + sha256(secret)[:16] )[:16]
```

不含行号，所以往文件顶部加注释、格式化代码、挪动代码块都不会让基线失效；
只有**换了密钥值、换了路径、换了规则**才会被当成新泄露。

```bash
# 第一次接入老仓库：把存量全部记下并提交基线文件
python keyhound-cli.py --init-baseline --reason "legacy test fixtures" .
git add .keyhound-baseline.json && git commit -m "chore: accept existing findings"

# 此后日常扫描：只报新增
python keyhound-cli.py .

# 确认某批新命中也是可接受的，追加进基线
python keyhound-cli.py --update-baseline --reason "reviewed with security team" .

# 临时想看全量
python keyhound-cli.py --no-baseline .
```

`.keyhound-baseline.json` 里只保存**脱敏值**、规则 id、相对路径和指纹，不含原文，
可以放心提交到仓库供团队共享。本仓库自己也用这个机制跳过文档与测试里的合成密钥。

---

## 集成

### pre-commit

本项目已带 `.pre-commit-hooks.yaml`，在目标仓库的 `.pre-commit-config.yaml` 里加：

```yaml
repos:
  - repo: https://github.com/yuezihao85/keyhound
    rev: v0.1.0
    hooks:
      - id: keyhound          # language: python，装好 console_script
      # 或 - id: keyhound-system   # language: system，只要 PATH 上有 python
```

也可以不装框架，直接把 [`examples/scan-diff.sh`](examples/scan-diff.sh) 放进
`.git/hooks/pre-commit`：

```bash
#!/usr/bin/env sh
git diff --cached | python /path/to/keyhound/keyhound-cli.py -
```

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.11" }
- name: Scan for secrets
  run: python keyhound-cli.py --format sarif --output keyhound.sarif .
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: keyhound.sarif }
```

命中会让 `run` 步骤返回 1；配合 `if: always()` 仍能上传结果，在
**Security → Code scanning** 里看到逐条告警。完整例子见
[`examples/github-action.yml`](examples/github-action.yml)。

### 作为库使用

```python
from keyhound import Config, RuleSet, Scanner, render_json

cfg = Config(min_entropy=4.0, exclude=["*.min.js"])
cfg.build_allowlist()
result = Scanner(cfg, RuleSet()).scan(["."])
print(render_json(result))
```

完整示例：[`examples/library_usage.py`](examples/library_usage.py)。

---

## 输出示例

`console`（纯 ASCII，Windows cp936 / CI 日志都不会乱码）：

```
[!] 7 potential secrets found

sample.env
  sample.env:2:19  critical  aws-access-key-id  AWS access key ID (AKIA / ASIA)
    value: AKIA************LE  fp: d99c77d79eb4f638
  sample.env:3:23  critical  aws-secret-access-key  AWS secret access key (40-char base64)
    value: wJal************EY  fp: 877377500b2bbabd
  sample.env:4:14  critical  github-pat  GitHub personal access token (classic)
    value: ghp_************89  fp: 5aebb359c9b6ede2
  sample.env:5:12  critical  stripe-live-key  Stripe live secret / restricted key
    value: sk_l************aZ  fp: 619c86208e848e17
  ...

1 file / 17 lines scanned  (critical=5, high=1, medium=1, low=0)
```

启用基线后，已被记录的命中不再列出，只在末尾追加一行
`22 baseline-suppressed findings`（数量随实际条目变化）；`--show-suppressed`
可以把它们逐条展开。

`json` 顶层结构：`version / tool / tool_version / scan_root / summary / findings / errors`，
每条 finding 为 `rule_id, description, severity, path, line, column, masked, fingerprint, tags`。

`sarif` 为标准 2.1.0：`runs[0].tool.driver.rules[]` + `results[]`，
每条结果带 `partialFingerprints["keyhoundSecretHash/v1"]`，GitHub 可去重跟踪。

---

## 内置规则

| 规则 id | 级别 | 检测对象 |
|---|---|---|
| `aws-access-key-id` | critical | `AKIA` / `ASIA` 开头的 20 位 ID |
| `aws-secret-access-key` | critical | AWS secret key 上下文 + 40 位 base64 |
| `github-pat` | critical | `ghp_/gho_/ghu_/ghs_/ghr_` 经典 PAT |
| `github-fine-grained-pat` | critical | `github_pat_` 细粒度令牌 |
| `github-oauth` | high | GitHub OAuth client secret |
| `gitlab-pat` | critical | `glpat-` 令牌 |
| `slack-token` | high | `xox[abprs]-` 系列 |
| `slack-webhook` | high | `hooks.slack.com/services/...` |
| `stripe-live-key` | critical | `sk_live_` / `rk_live_` |
| `google-api-key` | high | `AIza` 开头的 39 位 key |
| `google-oauth-secret` | high | `GOCSPX-` |
| `private-key-block` | critical | PEM / OpenSSH 私钥头 |
| `jwt` | medium | `header.payload.signature` 三段式 |
| `npm-token` | high | `npm_` 36 位 |
| `pypi-token` | critical | `pypi-` 长令牌 |
| `sendgrid-api-key` | high | `SG.xxx.xxx` |
| `mailgun-api-key` | medium | `key-` + 32 位 |
| `twilio-api-key` | high | `SK` + 32 位 hex |
| `openai-api-key` | high | `sk-` / `sk-proj-` / `sk-ant-` |
| `connection-string-password` | critical | `postgres://user:pass@...` 等 DB URI |
| `generic-high-entropy-secret` | medium | 赋给 `token/secret/password/...` 的高熵值 |

---

## 处理误报

按推荐顺序：

1. **行内注释**：在同一行加 `keyhound:allow` 或 `nosec`（上下文白名单）。
2. **值白名单**：在 `.keyhound.json` 的 `allowlist` 加正则，例如 `"^ACME_[A-Z0-9_]+$"`。
3. **停用规则**：`--disable-rule generic-high-entropy-secret` 或 `disabled_rules`。
4. **基线**：`--init-baseline` / `--update-baseline` 接受存量。
5. **调阈值**：`--min-entropy 4.2 --min-length 24` 收紧通用规则。

---

## 开发与测试

```bash
# 标准库 unittest，无需安装 pytest
python -m unittest discover -s tests -v

# 也兼容 pytest
pytest -q

# 自扫描（本仓库自带基线）
python keyhound-cli.py .
```

目录结构：

```
keyhound/
├── keyhound/                 # 可 import 的包（仅标准库）
│   ├── cli.py                # argparse + 退出码
│   ├── config.py             # .keyhound.json
│   ├── entropy.py            # 香农熵 / 随机性判定
│   ├── ignore.py             # .gitignore 作用域匹配
│   ├── rules.py              # 21 条内置规则 + RuleSet
│   ├── scanner.py            # 文件遍历 / 命中 / 脱敏 / 指纹
│   ├── baseline.py           # 基线读写
│   └── reporters.py          # console / json / sarif
├── keyhound-cli.py           # 零安装入口
├── setup.py / pyproject.toml
├── .pre-commit-hooks.yaml
├── .github/workflows/ci.yml
├── examples/
└── tests/
```

---

## 发布前 checklist

仓库地址已统一为 `https://github.com/yuezihao85/keyhound`：README 徽章与克隆链接、
`setup.py` 的 `author` / `url` / `project_urls`、`cli.py` 的 `epilog`、
`reporters.py` 的 `informationUri`、`LICENSE` 版权行、以及各示例 yml 全部对齐。

推送前只剩两步：

- 打 tag：`git tag v0.1.0 && git push --tags`（pre-commit 的 `rev` 要用它）
- 推完确认 Actions 徽章变绿、Security → Code scanning 能收到 SARIF

> 注意：keyhound 是**提交前的护栏**，不是密钥管理的替代品。真泄露了应当先轮换凭据，
> 再从历史里清理；扫描器只能帮你少犯一次错。

## License

[MIT](LICENSE)
