<div align="center">

# Agent Threat Scanner

面向 Agent 资产的本地优先安全扫描器：从文件与目录中发现提示注入、命令执行、数据外传、敏感文件访问等风险。

[![CI](https://github.com/l3m0nc9/agent-threat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/l3m0nc9/agent-threat-scanner/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40l3m0nc9%2Fagent-threat-scanner)](https://www.npmjs.com/package/@l3m0nc9/agent-threat-scanner)
[![Node.js >=24](https://img.shields.io/badge/node-%3E%3D24-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.en.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

## 项目定位

Agent Threat Scanner 是 ESM + TypeScript 安全扫描库和 CLI，适合本地开发、代码审查和 CI。扫描器不会执行目标文件。

当前版本支持以文件或目录形式提供的 Agent Skill 内容；MCP 服务器配置和完整智能体项目的专用适配器已列入后续路线图。

## 为什么使用它

- **本地优先**：可传入内存文件，扫描器不会自行读取磁盘；API key 只在模型请求期间使用。
- **静态 + 语义**：quick 模式使用确定性规则；full 模式可叠加模型复核和行为分析。
- **面向风险**：覆盖命令执行、数据外传、密钥访问、持久化、权限提升和提示注入等 Agent 风险。
- **可嵌入**：导出 TypeScript API、Zod schema、稳定的风险 slug 和内容寻址 finding ID。
- **可审计**：报告保留分支状态、跳过文件、规则聚合、风险分数和 token 使用信息。

## 快速开始

要求 Node.js 24 或更高版本。

### 安装并运行 CLI

~~~bash
npm install @l3m0nc9/agent-threat-scanner

# 已安装到当前项目后运行
npx agent-threat-scan ./path/to/skill --quick

# 不安装到当前项目，直接运行一次
npx --yes --package @l3m0nc9/agent-threat-scanner agent-threat-scan ./path/to/skill --quick
~~~

quick 模式不需要 API key。目标可以是包含 SKILL.md 的目录，也可以是单个文件。

### 在 TypeScript 中使用

~~~ts
import { scanSkill } from "@l3m0nc9/agent-threat-scanner";

const report = await scanSkill({
  mode: "quick",
  files: [
    { path: "SKILL.md", content: "# Demo\nFormat local markdown files." }
  ]
});

console.log(report.verdict, report.riskScore);
~~~

如果由宿主读取磁盘路径：

~~~ts
const report = await scanSkill({
  mode: "quick",
  paths: ["./my-skill"]
});
~~~

files 和 paths 互斥。files 模式只处理调用方已经放入内存的内容。

## 扫描能力

当前内置 76 条静态规则，覆盖 11 类风险：

| 风险类别 | 典型信号 |
|---|---|
| remote_execution | 远程下载并执行、反连或命令拉取 |
| command_injection | shell、脚本解释器和危险参数拼接 |
| data_exfiltration | 未授权上传、外发和可疑遥测 |
| secret_access | 读取密钥、凭据、token 或认证文件 |
| persistence | 启动项、计划任务、钩子和持久化修改 |
| destructive | 删除、覆盖、破坏性系统操作 |
| obfuscation | 编码、混淆、隐藏载荷和可疑解码 |
| privilege_escalation | sudo、权限修改和高权限执行 |
| sensitive_file_access | SSH、云凭据、浏览器数据等敏感路径 |
| network_abuse | 可疑公网 IP、C2/OAST 域名和异常网络行为 |
| prompt_injection | 诱导模型越权、泄露上下文或改变安全边界 |

此外还包含文件级检查（高风险扩展名、超大内容、超长文件、隐藏文本、可疑公网 IP）以及 IOC 黑名单。

## 扫描模式

| 模式 | 适用场景 | 行为 |
|---|---|---|
| quick | 本地预检、提交前检查、无模型环境 | 静态规则 + 文件级检查，确定性强 |
| full | 高风险变更、发布前审查 | quick 结果 + lite 模型规则复核 + pro 模型行为分析 |

单个 SKILL.md 使用单文件模型分析；多文件输入使用带 list_files、read_file、grep 工具的行为分析循环，以追踪跨文件关系。模型分支失败时会保留静态结果并将报告标记为 partial。

## CLI

~~~text
agent-threat-scan <file-or-directory> [options]
~~~

常用参数：

| 参数 | 说明 |
|---|---|
| --quick | 仅运行静态扫描 |
| --mode <quick\|full> | 指定扫描模式 |
| --config <file> | 配置文件，默认 ./.agent-threat-scanner.json |
| --locale <locale> | zh-CN、en-US、ja-JP、ko-KR |
| --json | 输出完整 JSON 报告 |
| --output <file> | 将报告写入文件 |
| --verbose | 输出扫描过程日志 |
| --provider <name> | openai-responses、openai-completions 或 anthropic |
| --endpoint <url> | 模型 API 基础地址 |
| --lite-model <name> | 规则复核和语义去重模型 |
| --pro-model <name> | 行为分析模型 |
| --timeout-ms <ms> | 单次模型调用超时，默认 120000 |
| --context-window-tokens <n> | 调整发送给模型的内容上限 |
| --max-agent-turns <n> | 多文件行为分析的最大工具调用轮数，默认 12 |

~~~bash
agent-threat-scan ./my-skill --quick
agent-threat-scan ./my-skill --quick --json --output report.json
agent-threat-scan ./my-skill --config .agent-threat-scanner.json
~~~

## Full 模式与模型配置

支持 OpenAI Responses、OpenAI Chat Completions 和 Anthropic Messages。可以复制 [配置模板](.agent-threat-scanner.example.json)：

~~~json
{
  "mode": "full",
  "locale": "zh-CN",
  "model": {
    "provider": "openai-responses",
    "endpoint": "https://api.openai.com/v1",
    "apiKey": "sk-...",
    "liteModel": "gpt-4o-mini",
    "proModel": "gpt-4o"
  }
}
~~~

也可以使用环境变量：

~~~bash
export LLM_PROVIDER=openai-responses
export LLM_ENDPOINT=https://api.openai.com/v1
export LLM_API_KEY=sk-...
export LLM_LITE_MODEL=gpt-4o-mini
export LLM_PRO_MODEL=gpt-4o

agent-threat-scan ./my-skill --mode full
~~~

| 变量 | 必填 | 默认值 |
|---|---:|---|
| LLM_PROVIDER | 否 | 根据 endpoint 自动探测 |
| LLM_ENDPOINT | full 是 | 无 |
| LLM_API_KEY | full 是 | 无 |
| LLM_LITE_MODEL | full 是 | 无 |
| LLM_PRO_MODEL | full 是 | 无 |
| LLM_TIMEOUT_MS | 否 | 120000 |
| LLM_CONTEXT_WINDOW_TOKENS | 否 | 自动限制 |
| LLM_MAX_AGENT_TURNS | 否 | 12 |
| LLM_LOCALE | 否 | zh-CN |

## 报告与评分

报告通过 Zod schema 校验，核心字段包括：

- verdict：allow、warn、block 或 unknown
- riskScore：0–100，分数越高越安全
- threatLevel：none、low、medium、high、critical
- findings：风险类别、严重度、规则或模型来源、位置和修复建议
- rules：按 ruleId 聚合的静态命中和逐条匹配
- branches：静态、规则复核、单文件分析、多文件分析的状态
- skippedFiles：二进制或无法分析文件及原因
- contentHash：排序后的 path + content 的 SHA-256
- tokenUsage：请求数、返回 usage 的请求数及按模型/分支的 token 明细

评分采用扣分制：

~~~text
riskScore = max(0, 100 - staticRuleWeights - modelFindingWeights)
~~~

部分扫描且没有发现时返回 unknown，不会把不完整结果误判为安全。

## 隐私与安全边界

- 扫描器不会执行目标文件或脚本。
- files 模式下，扫描器不会自行访问磁盘。
- paths 模式由宿主明确授权读取指定路径。
- API key 不会写入报告、日志或持久化存储。
- 报告摘录会进行密钥脱敏；finding ID 使用内容哈希，不包含路径。
- 当前版本是静态/模型辅助分析，不提供沙箱执行、动态网络探测或运行时防护。

不要把真实 API key 写入仓库；推荐使用环境变量、未提交的 .agent-threat-scanner.json 或 CI secret。

## CI 集成

~~~yaml
- name: Scan agent artifacts
  run: |
    npm ci
    npm run build
    npx agent-threat-scan ./path/to/skill --quick --json --output agent-threat-report.json
~~~

发布前可以使用 --mode full，并将 block 或高危结果接入组织自己的质量门禁。

## 路线图

- [ ] MCP server / tool manifest 解析与风险检查
- [ ] Agent 配置、工具权限和 prompt 组合分析
- [ ] auto 模式：按输入类型自动选择 Skill、MCP 或 Agent 适配器
- [ ] SARIF、JUnit 和 GitHub PR 注释输出
- [ ] 可配置规则包、组织级 allowlist 和 baseline
- [ ] 动态分析与隔离执行（独立安全边界）

路线图不代表当前版本已经提供对应能力。

## 开发

~~~bash
npm ci --registry=https://registry.npmmirror.com
npm run build
npm run typecheck
npm run lint
npm test
npm pack --dry-run
~~~

示例脚本位于 examples/；规则和提示词位于 src/rules/ 与 src/model/prompts/。

## 项目结构

~~~text
src/
├── scanner.ts       扫描编排
├── types.ts         Zod 输入/输出 schema
├── rules/           静态规则与元数据
├── detection/       检查、评分、去重、报告聚合
├── model/           模型传输、行为分析和提示词
└── i18n/            多语言资源
~~~

欢迎提交 Issue 和 Pull Request。安全问题请阅读 [SECURITY.md](SECURITY.md)，贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

[MIT](LICENSE) © l3m0nc9 contributors
