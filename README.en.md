<div align="center">

# Agent Threat Scanner

A local-first security scanner for agent artifacts. Detect prompt injection, command execution, data exfiltration, sensitive-file access, and related threats before an agent uses a file or tool.

[![CI](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40estelwalks%2Fagent-threat-scanner)](https://www.npmjs.com/package/@estelwalks/agent-threat-scanner)
[![Node.js >=24](https://img.shields.io/badge/node-%3E%3D24-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[中文](README.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

## What this project is

Agent Threat Scanner is an ESM + TypeScript library and CLI for local development, code review, and CI. It never executes scanned files.

The current release accepts agent Skill content as files or directories. Dedicated adapters for MCP server configurations and complete agent projects are planned; they are not part of the current release.

## Why use it

- **Local-first**: pass in-memory files so the scanner does not read from disk; API keys are used only during model requests.
- **Static + semantic**: quick mode is deterministic; full mode can add model verification and behavioral analysis.
- **Risk-oriented**: checks command execution, exfiltration, secrets, persistence, privilege escalation, prompt injection, and more.
- **Embeddable**: exports TypeScript APIs, Zod schemas, stable risk slugs, and content-addressed finding IDs.
- **Auditable**: reports include branch status, skipped files, rule aggregation, scores, and token-usage details.

## Quick start

Requires Node.js 24 or newer.

### Install and run the CLI

~~~bash
npm install @estelwalks/agent-threat-scanner

# Run after installing in the current project
npx agent-threat-scan ./path/to/skill --quick

# Run once without adding it to the current project
npx --yes --package @estelwalks/agent-threat-scanner agent-threat-scan ./path/to/skill --quick
~~~

Quick mode needs no API key. The target may be a directory containing SKILL.md or a single file.

### Use the library

~~~ts
import { scanSkill } from "@estelwalks/agent-threat-scanner";

const report = await scanSkill({
  mode: "quick",
  files: [
    { path: "SKILL.md", content: "# Demo\nFormat local markdown files." }
  ]
});

console.log(report.verdict, report.riskScore);
~~~

If the host intentionally reads a path from disk:

~~~ts
const report = await scanSkill({
  mode: "quick",
  paths: ["./my-skill"]
});
~~~

files and paths are mutually exclusive. In files mode, the library only processes content already supplied by the caller.

## Detection coverage

The current engine ships 76 static rules across 11 risk kinds:

| Risk kind | Examples |
|---|---|
| remote_execution | remote download-and-execute, callbacks, command retrieval |
| command_injection | shell/interpreter invocation and unsafe argument construction |
| data_exfiltration | unauthorized uploads, outbound transfer, suspicious telemetry |
| secret_access | credentials, tokens, cloud keys, authentication files |
| persistence | startup entries, scheduled tasks, hooks, persistent changes |
| destructive | deletion, overwrite, destructive system operations |
| obfuscation | encoded or hidden payloads and suspicious decoding |
| privilege_escalation | sudo, permission changes, privileged execution |
| sensitive_file_access | SSH, cloud credentials, browser data, sensitive paths |
| network_abuse | suspicious public IPs, C2/OAST domains, unusual network behavior |
| prompt_injection | attempts to override instructions, leak context, or weaken boundaries |

File-level checks cover risky extensions, oversized content, very long files, hidden text, and suspicious public IPs. The engine also includes an IOC blocklist.

## Scan modes

| Mode | Use it for | Behavior |
|---|---|---|
| quick | pre-commit checks and environments without a model | static rules and file-level checks |
| full | high-risk changes and release review | quick results plus lite-model rule verification and pro-model behavioral analysis |

A single SKILL.md uses single-file analysis. Multi-file input uses a behavioral loop with list_files, read_file, and grep tools to trace cross-file relationships. If a model branch fails, static results are preserved and the report is marked partial.

## CLI

~~~text
agent-threat-scan <file-or-directory> [options]
~~~

| Option | Description |
|---|---|
| --quick | static-only scan |
| --mode <quick\|full> | select scan mode |
| --config <file> | config file, default ./.agent-threat-scanner.json |
| --locale <locale> | zh-CN, en-US, ja-JP, or ko-KR |
| --json | print the full JSON report |
| --output <file> | write the report to a file |
| --verbose | print scan progress to stderr |
| --provider <name> | openai-responses, openai-completions, or anthropic |
| --endpoint <url> | model API base URL |
| --lite-model <name> | rule-verification and semantic-dedup model |
| --pro-model <name> | behavioral-analysis model |
| --timeout-ms <ms> | per-call timeout, default 120000 |
| --context-window-tokens <n> | raise the model content budget |
| --max-agent-turns <n> | max multi-file tool-call turns, default 12 |

~~~bash
agent-threat-scan ./my-skill --quick
agent-threat-scan ./my-skill --quick --json --output report.json
agent-threat-scan ./my-skill --config .agent-threat-scanner.json
~~~

## Full mode and model configuration

Supported protocols are OpenAI Responses, OpenAI Chat Completions, and Anthropic Messages.

Copy the [configuration template](.agent-threat-scanner.example.json):

~~~json
{
  "mode": "full",
  "locale": "en-US",
  "model": {
    "provider": "openai-responses",
    "endpoint": "https://api.openai.com/v1",
    "apiKey": "sk-...",
    "liteModel": "gpt-4o-mini",
    "proModel": "gpt-4o"
  }
}
~~~

Or configure the model with environment variables:

~~~bash
export LLM_PROVIDER=openai-responses
export LLM_ENDPOINT=https://api.openai.com/v1
export LLM_API_KEY=sk-...
export LLM_LITE_MODEL=gpt-4o-mini
export LLM_PRO_MODEL=gpt-4o

agent-threat-scan ./my-skill --mode full
~~~

| Variable | Required | Default |
|---|---:|---|
| LLM_PROVIDER | no | inferred from endpoint |
| LLM_ENDPOINT | full only | none |
| LLM_API_KEY | full only | none |
| LLM_LITE_MODEL | full only | none |
| LLM_PRO_MODEL | full only | none |
| LLM_TIMEOUT_MS | no | 120000 |
| LLM_CONTEXT_WINDOW_TOKENS | no | automatic cap |
| LLM_MAX_AGENT_TURNS | no | 12 |
| LLM_LOCALE | no | zh-CN |

## Reports and scoring

Reports are validated by exported Zod schemas. Important fields include:

- verdict: allow, warn, block, or unknown
- riskScore: 0–100; higher is safer
- threatLevel: none, low, medium, high, or critical
- findings: normalized kind, severity, source, location, message, and remediation
- rules: static findings aggregated by ruleId with individual matches
- branches: static, rule review, single-file analysis, and multi-file analysis status
- skippedFiles: files that were not analyzed and the reason
- contentHash: SHA-256 over sorted path + content pairs
- tokenUsage: request counts and per-model/per-branch token details

Scoring is deduction-based:

~~~text
riskScore = max(0, 100 - staticRuleWeights - modelFindingWeights)
~~~

A partial scan with no findings returns unknown; incomplete evidence is never treated as safe.

## Privacy and security boundary

- Scanned files and scripts are never executed.
- files mode does not perform disk I/O inside the library.
- paths mode reads only paths explicitly supplied by the host.
- API keys are not written to reports, logs, or persistent storage.
- Excerpts are secret-redacted; finding IDs use content hashes and do not contain paths.
- This release provides static and model-assisted analysis, not sandbox execution, dynamic network probing, or runtime protection.

Never commit a real API key. Use environment variables, an untracked .agent-threat-scanner.json, or CI secrets.

## CI integration

~~~yaml
- name: Scan agent artifacts
  run: |
    npm ci
    npm run build
    npx agent-threat-scan ./path/to/skill --quick --json --output agent-threat-report.json
~~~

For release gates, use --mode full and connect block or high-severity results to your own policy.

## Roadmap

- [ ] MCP server and tool-manifest parsing
- [ ] Agent configuration, tool-permission, and prompt-composition analysis
- [ ] auto mode for Skill, MCP, and Agent adapters
- [ ] SARIF, JUnit, and GitHub pull-request annotations
- [ ] Configurable rule packs, organizational allowlists, and baselines
- [ ] Isolated dynamic analysis with an explicit security boundary

Roadmap items are not available in the current release unless documented elsewhere.

## Development

~~~bash
npm ci --registry=https://registry.npmmirror.com
npm run build
npm run typecheck
npm run lint
npm test
npm pack --dry-run
~~~

Examples live in examples/. Rules and prompts live in src/rules/ and src/model/prompts/.

## Project layout

~~~text
src/
├── scanner.ts       scan orchestration
├── types.ts         Zod input/output schemas
├── rules/           static rules and metadata
├── detection/       checks, scoring, deduplication, report aggregation
├── model/           model transports, behavioral analysis, prompts
└── i18n/            localized resources
~~~

Contributions are welcome. Read [SECURITY.md](SECURITY.md) for vulnerability reports and [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow.

## License

[MIT](LICENSE) © estelwalks contributors
