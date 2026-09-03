<div align="center">

# Agent Threat Scanner

Agent のファイル資産をローカル優先で検査するセキュリティスキャナです。プロンプトインジェクション、コマンド実行、データ外部送信、機密ファイルアクセスなどを検出します。

[![CI](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40estelwalks%2Fagent-threat-scanner)](https://www.npmjs.com/package/@estelwalks/agent-threat-scanner)
[![Node.js >=24](https://img.shields.io/badge/node-%3E%3D24-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[中文](README.md) · [English](README.en.md) · [한국어](README.ko.md)

</div>

## 概要

Agent Threat Scanner は ESM + TypeScript のライブラリと CLI です。ローカル開発、コードレビュー、CI で利用でき、検査対象のファイルを実行しません。

現行リリースは、ファイルまたはディレクトリとして渡された Agent Skill の内容を対象にします。MCP サーバー設定と完全な Agent プロジェクトの専用アダプタはロードマップに含まれます。

## 特徴

- **ローカル優先**：メモリ上のファイルを渡せます。API キーはモデルリクエスト中だけ使用します。
- **静的 + セマンティック**：quick は決定的なルール、full はモデルによるルール確認と振る舞い分析を追加します。
- **リスク中心**：コマンド実行、データ外部送信、シークレット、永続化、権限昇格、プロンプトインジェクションを検査します。
- **組み込み可能**：TypeScript API、Zod schema、安定した risk slug、内容アドレス型の finding ID を提供します。
- **監査可能**：分岐の状態、スキップしたファイル、ルール集計、スコア、token 使用量をレポートします。

## クイックスタート

Node.js 24 以降が必要です。

~~~bash
npm install @estelwalks/agent-threat-scanner

npx agent-threat-scan ./path/to/skill --quick

# プロジェクトへ追加せず一度だけ実行
npx --yes --package @estelwalks/agent-threat-scanner agent-threat-scan ./path/to/skill --quick
~~~

quick モードに API キーは不要です。対象は SKILL.md を含むディレクトリ、または単一ファイルです。

### TypeScript から利用

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

ホスト側で読み取りを許可したパスを渡すこともできます。

~~~ts
const report = await scanSkill({
  mode: "quick",
  paths: ["./my-skill"]
});
~~~

files と paths は同時に指定できません。files モードでは呼び出し側が渡した内容だけを処理します。

## 検出範囲

現行エンジンには 76 の静的ルールと 11 種類のリスクがあります。

| リスク | 例 |
|---|---|
| remote_execution | リモート取得後の実行、コールバック、コマンド取得 |
| command_injection | shell・インタプリタ呼び出し、危険な引数生成 |
| data_exfiltration | 未承認アップロード、外部送信、不審な telemetry |
| secret_access | 認証情報、token、クラウドキー、認証ファイル |
| persistence | 起動項目、スケジュールタスク、hook、永続的変更 |
| destructive | 削除、上書き、破壊的なシステム操作 |
| obfuscation | エンコード、隠し payload、不審なデコード |
| privilege_escalation | sudo、権限変更、高権限実行 |
| sensitive_file_access | SSH、クラウド認証情報、ブラウザデータ |
| network_abuse | 不審な IP、C2/OAST ドメイン、異常な通信 |
| prompt_injection | 指示の上書き、コンテキスト漏えい、境界の弱体化 |

危険な拡張子、過大な内容、極端に長いファイル、隠しテキスト、不審な公開 IP のファイル検査と IOC ブロックリストも含みます。

## スキャンモード

| モード | 用途 | 動作 |
|---|---|---|
| quick | pre-commit、ローカル確認、モデルなしの環境 | 静的ルール + ファイル検査 |
| full | 高リスク変更、リリース前レビュー | quick + lite モデルのルール確認 + pro モデルの振る舞い分析 |

単一の SKILL.md には単一ファイル分析を、多ファイル入力には list_files、read_file、grep を使う振る舞い分析ループを実行します。モデル分岐に失敗しても静的結果は保持され、レポートは partial になります。

## CLI

~~~text
agent-threat-scan <file-or-directory> [options]
~~~

| オプション | 説明 |
|---|---|
| --quick | 静的スキャンのみ |
| --mode <quick\|full> | スキャンモード |
| --config <file> | 設定ファイル。既定値は ./.agent-threat-scanner.json |
| --locale <locale> | zh-CN、en-US、ja-JP、ko-KR |
| --json | 完全な JSON レポートを出力 |
| --output <file> | レポートをファイルへ保存 |
| --verbose | 進行ログを stderr に出力 |
| --provider <name> | openai-responses、openai-completions、anthropic |
| --endpoint <url> | モデル API のベース URL |
| --lite-model <name> | ルール確認・セマンティック重複除去モデル |
| --pro-model <name> | 振る舞い分析モデル |
| --timeout-ms <ms> | 呼び出しタイムアウト。既定値 120000 |
| --context-window-tokens <n> | モデルへ送る内容上限を調整 |
| --max-agent-turns <n> | 多ファイル分析の最大 tool-call 回数。既定値 12 |

~~~bash
agent-threat-scan ./my-skill --quick
agent-threat-scan ./my-skill --quick --json --output report.json
agent-threat-scan ./my-skill --config .agent-threat-scanner.json
~~~

## Full モードのモデル設定

OpenAI Responses、OpenAI Chat Completions、Anthropic Messages に対応します。 [設定テンプレート](.agent-threat-scanner.example.json) をコピーできます。

~~~json
{
  "mode": "full",
  "locale": "ja-JP",
  "model": {
    "provider": "openai-responses",
    "endpoint": "https://api.openai.com/v1",
    "apiKey": "sk-...",
    "liteModel": "gpt-4o-mini",
    "proModel": "gpt-4o"
  }
}
~~~

環境変数でも設定できます。

~~~bash
export LLM_PROVIDER=openai-responses
export LLM_ENDPOINT=https://api.openai.com/v1
export LLM_API_KEY=sk-...
export LLM_LITE_MODEL=gpt-4o-mini
export LLM_PRO_MODEL=gpt-4o

agent-threat-scan ./my-skill --mode full
~~~

| 変数 | 必須 | 既定値 |
|---|---:|---|
| LLM_PROVIDER | いいえ | endpoint から推測 |
| LLM_ENDPOINT | full のみ | なし |
| LLM_API_KEY | full のみ | なし |
| LLM_LITE_MODEL | full のみ | なし |
| LLM_PRO_MODEL | full のみ | なし |
| LLM_TIMEOUT_MS | いいえ | 120000 |
| LLM_CONTEXT_WINDOW_TOKENS | いいえ | 自動上限 |
| LLM_MAX_AGENT_TURNS | いいえ | 12 |
| LLM_LOCALE | いいえ | zh-CN |

## レポートとスコア

Zod schema で検証されたレポートには、verdict、riskScore、threatLevel、findings、rules、branches、skippedFiles、contentHash、tokenUsage が含まれます。

- riskScore は 0–100 で、高いほど安全です。
- verdict は allow、warn、block、unknown のいずれかです。
- finding にはリスク種別、重大度、検出元、位置、メッセージ、修正案があります。
- contentHash はソートした path + content の SHA-256 です。
- partial スキャンで検出結果がない場合は unknown となり、不完全な証拠を安全とは判定しません。

~~~text
riskScore = max(0, 100 - staticRuleWeights - modelFindingWeights)
~~~

## プライバシーと安全境界

- 検査対象のファイルやスクリプトを実行しません。
- files モードではライブラリ内部からディスクへアクセスしません。
- paths モードではホストが明示したパスだけを読み取ります。
- API キーをレポート、ログ、永続ストレージへ書き込みません。
- 抜粋はシークレットをマスキングし、finding ID にパスを含めません。
- 現行リリースは静的・モデル支援分析であり、sandbox、動的ネットワーク探索、runtime 防御は提供しません。

## CI での利用

~~~yaml
- name: Scan agent artifacts
  run: |
    npm ci
    npm run build
    npx agent-threat-scan ./path/to/skill --quick --json --output agent-threat-report.json
~~~

リリースゲートでは --mode full と block / high の結果を組織のポリシーに接続してください。

## ロードマップ

- [ ] MCP server と tool manifest の解析
- [ ] Agent 設定、tool 権限、prompt 組み合わせの分析
- [ ] Skill、MCP、Agent を自動選択する auto モード
- [ ] SARIF、JUnit、GitHub Pull Request コメント
- [ ] ルールパック、組織 allowlist、baseline
- [ ] 明確な安全境界を持つ隔離動的分析

ロードマップの項目は、別途明記されない限り現行リリースには含まれません。

## 開発

~~~bash
npm ci --registry=https://registry.npmmirror.com
npm run build
npm run typecheck
npm run lint
npm test
npm pack --dry-run
~~~

サンプルは examples/、ルールと prompt は src/rules/ と src/model/prompts/ にあります。

## コントリビュート

Issue と Pull Request を歓迎します。脆弱性の報告は [SECURITY.md](SECURITY.md)、開発手順は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## ライセンス

[MIT](LICENSE) © estelwalks contributors
