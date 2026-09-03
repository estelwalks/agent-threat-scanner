<div align="center">

# Agent Threat Scanner

에이전트 파일 자산을 로컬 우선으로 검사하는 보안 스캐너입니다. 프롬프트 인젝션, 명령 실행, 데이터 유출, 민감 파일 접근과 같은 위협을 찾습니다.

[![CI](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/estelwalks/agent-threat-scanner/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40estelwalks%2Fagent-threat-scanner)](https://www.npmjs.com/package/@estelwalks/agent-threat-scanner)
[![Node.js >=24](https://img.shields.io/badge/node-%3E%3D24-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[中文](README.md) · [English](README.en.md) · [日本語](README.ja.md)

</div>

## 프로젝트 소개

Agent Threat Scanner는 ESM + TypeScript 라이브러리와 CLI입니다. 로컬 개발, 코드 리뷰, CI에서 사용할 수 있으며 검사 대상 파일을 실행하지 않습니다.

현재 릴리스는 파일 또는 디렉터리로 제공되는 Agent Skill 콘텐츠를 지원합니다. MCP 서버 설정과 전체 에이전트 프로젝트를 위한 전용 어댑터는 로드맵에 포함되어 있습니다.

## 주요 특징

- **로컬 우선**: 메모리 파일을 전달할 수 있고, API 키는 모델 요청 중에만 사용됩니다.
- **정적 + 의미 분석**: quick은 결정적 규칙을, full은 모델 규칙 검증과 행동 분석을 추가합니다.
- **위험 중심**: 명령 실행, 데이터 유출, 시크릿, 지속성, 권한 상승, 프롬프트 인젝션 등을 검사합니다.
- **임베드 가능**: TypeScript API, Zod schema, 안정적인 risk slug, 콘텐츠 주소 기반 finding ID를 제공합니다.
- **감사 가능**: 분기 상태, 건너뛴 파일, 규칙 집계, 점수, token 사용량을 보고합니다.

## 빠른 시작

Node.js 24 이상이 필요합니다.

~~~bash
npm install @estelwalks/agent-threat-scanner

npx agent-threat-scan ./path/to/skill --quick

# 현재 프로젝트에 추가하지 않고 한 번만 실행
npx --yes --package @estelwalks/agent-threat-scanner agent-threat-scan ./path/to/skill --quick
~~~

quick 모드에는 API 키가 필요하지 않습니다. 대상은 SKILL.md를 포함한 디렉터리 또는 단일 파일입니다.

### TypeScript에서 사용

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

호스트가 읽기를 허용한 디스크 경로를 전달할 수도 있습니다.

~~~ts
const report = await scanSkill({
  mode: "quick",
  paths: ["./my-skill"]
});
~~~

files와 paths는 동시에 사용할 수 없습니다. files 모드에서는 호출자가 이미 전달한 콘텐츠만 처리합니다.

## 탐지 범위

현재 엔진은 76개의 정적 규칙과 11가지 위험 유형을 제공합니다.

| 위험 유형 | 예시 |
|---|---|
| remote_execution | 원격 다운로드 후 실행, 콜백, 명령 가져오기 |
| command_injection | shell·인터프리터 호출, 위험한 인자 조합 |
| data_exfiltration | 무단 업로드, 외부 전송, 의심스러운 telemetry |
| secret_access | 자격 증명, token, 클라우드 키, 인증 파일 |
| persistence | 시작 항목, 예약 작업, hook, 영구 변경 |
| destructive | 삭제, 덮어쓰기, 파괴적 시스템 작업 |
| obfuscation | 인코딩, 숨겨진 payload, 의심스러운 디코딩 |
| privilege_escalation | sudo, 권한 변경, 고권한 실행 |
| sensitive_file_access | SSH, 클라우드 자격 증명, 브라우저 데이터 |
| network_abuse | 의심스러운 IP, C2/OAST 도메인, 비정상 네트워크 |
| prompt_injection | 지시 덮어쓰기, 컨텍스트 유출, 경계 약화 |

위험한 확장자, 지나치게 큰 콘텐츠, 매우 긴 파일, 숨겨진 텍스트, 의심스러운 공개 IP에 대한 파일 수준 검사와 IOC 차단 목록도 포함합니다.

## 스캔 모드

| 모드 | 용도 | 동작 |
|---|---|---|
| quick | pre-commit, 로컬 확인, 모델이 없는 환경 | 정적 규칙 + 파일 수준 검사 |
| full | 고위험 변경, 릴리스 전 검토 | quick + lite 모델 규칙 검증 + pro 모델 행동 분석 |

단일 SKILL.md는 단일 파일 분석을 사용합니다. 여러 파일을 입력하면 list_files, read_file, grep 도구를 사용하는 행동 분석 루프로 파일 간 관계를 추적합니다. 모델 분기가 실패해도 정적 결과는 보존되며 보고서는 partial로 표시됩니다.

## CLI

~~~text
agent-threat-scan <file-or-directory> [options]
~~~

| 옵션 | 설명 |
|---|---|
| --quick | 정적 스캔만 실행 |
| --mode <quick\|full> | 스캔 모드 선택 |
| --config <file> | 설정 파일, 기본값 ./.agent-threat-scanner.json |
| --locale <locale> | zh-CN, en-US, ja-JP, ko-KR |
| --json | 전체 JSON 보고서 출력 |
| --output <file> | 보고서를 파일에 저장 |
| --verbose | stderr에 진행 로그 출력 |
| --provider <name> | openai-responses, openai-completions, anthropic |
| --endpoint <url> | 모델 API 기본 URL |
| --lite-model <name> | 규칙 검증·의미 중복 제거 모델 |
| --pro-model <name> | 행동 분석 모델 |
| --timeout-ms <ms> | 호출 제한 시간, 기본값 120000 |
| --context-window-tokens <n> | 모델에 보내는 콘텐츠 상한 조정 |
| --max-agent-turns <n> | 다중 파일 분석의 최대 tool-call 횟수, 기본값 12 |

~~~bash
agent-threat-scan ./my-skill --quick
agent-threat-scan ./my-skill --quick --json --output report.json
agent-threat-scan ./my-skill --config .agent-threat-scanner.json
~~~

## Full 모드와 모델 설정

OpenAI Responses, OpenAI Chat Completions, Anthropic Messages를 지원합니다. [설정 템플릿](.agent-threat-scanner.example.json)을 복사해 사용할 수 있습니다.

~~~json
{
  "mode": "full",
  "locale": "ko-KR",
  "model": {
    "provider": "openai-responses",
    "endpoint": "https://api.openai.com/v1",
    "apiKey": "sk-...",
    "liteModel": "gpt-4o-mini",
    "proModel": "gpt-4o"
  }
}
~~~

환경 변수로도 설정할 수 있습니다.

~~~bash
export LLM_PROVIDER=openai-responses
export LLM_ENDPOINT=https://api.openai.com/v1
export LLM_API_KEY=sk-...
export LLM_LITE_MODEL=gpt-4o-mini
export LLM_PRO_MODEL=gpt-4o

agent-threat-scan ./my-skill --mode full
~~~

| 변수 | 필수 | 기본값 |
|---|---:|---|
| LLM_PROVIDER | 아니요 | endpoint에서 추론 |
| LLM_ENDPOINT | full만 | 없음 |
| LLM_API_KEY | full만 | 없음 |
| LLM_LITE_MODEL | full만 | 없음 |
| LLM_PRO_MODEL | full만 | 없음 |
| LLM_TIMEOUT_MS | 아니요 | 120000 |
| LLM_CONTEXT_WINDOW_TOKENS | 아니요 | 자동 상한 |
| LLM_MAX_AGENT_TURNS | 아니요 | 12 |
| LLM_LOCALE | 아니요 | zh-CN |

## 보고서와 점수

보고서는 내보낸 Zod schema로 검증되며 verdict, riskScore, threatLevel, findings, rules, branches, skippedFiles, contentHash, tokenUsage를 포함합니다.

- riskScore는 0–100이며 높을수록 안전합니다.
- verdict는 allow, warn, block, unknown 중 하나입니다.
- finding에는 위험 유형, 심각도, 출처, 위치, 메시지, 해결 방법이 있습니다.
- contentHash는 정렬된 path + content의 SHA-256입니다.
- partial 스캔에서 발견 항목이 없으면 unknown을 반환하며, 불완전한 증거를 안전하다고 판단하지 않습니다.

~~~text
riskScore = max(0, 100 - staticRuleWeights - modelFindingWeights)
~~~

## 개인정보와 보안 경계

- 검사 대상 파일과 스크립트를 실행하지 않습니다.
- files 모드에서는 라이브러리가 디스크에 접근하지 않습니다.
- paths 모드에서는 호스트가 명시한 경로만 읽습니다.
- API 키를 보고서, 로그, 영구 저장소에 기록하지 않습니다.
- 발췌 내용은 시크릿을 마스킹하며 finding ID에 경로를 포함하지 않습니다.
- 현재 릴리스는 정적·모델 보조 분석을 제공하며 sandbox 실행, 동적 네트워크 탐색, 런타임 방어는 제공하지 않습니다.

실제 API 키를 커밋하지 마세요. 환경 변수, 추적하지 않는 .agent-threat-scanner.json 또는 CI secret을 사용하세요.

## CI 통합

~~~yaml
- name: Scan agent artifacts
  run: |
    npm ci
    npm run build
    npx agent-threat-scan ./path/to/skill --quick --json --output agent-threat-report.json
~~~

릴리스 게이트에서는 --mode full을 사용하고 block 또는 high 결과를 조직의 정책에 연결하세요.

## 로드맵

- [ ] MCP server 및 tool manifest 파싱
- [ ] Agent 설정, tool 권한, prompt 조합 분석
- [ ] Skill, MCP, Agent 어댑터를 자동 선택하는 auto 모드
- [ ] SARIF, JUnit, GitHub Pull Request 주석
- [ ] 사용자 정의 규칙 팩, 조직 allowlist, baseline
- [ ] 명확한 안전 경계를 갖춘 격리 동적 분석

로드맵 항목은 별도 문서에 명시되지 않는 한 현재 릴리스에 포함되지 않습니다.

## 개발

~~~bash
npm ci --registry=https://registry.npmmirror.com
npm run build
npm run typecheck
npm run lint
npm test
npm pack --dry-run
~~~

예제는 examples/에, 규칙과 prompt는 src/rules/ 및 src/model/prompts/에 있습니다.

## 프로젝트 구조

~~~text
src/
├── scanner.ts       스캔 오케스트레이션
├── types.ts         Zod 입력/출력 schema
├── rules/           정적 규칙과 메타데이터
├── detection/       검사, 점수, 중복 제거, 보고서 집계
├── model/           모델 전송, 행동 분석, prompt
└── i18n/            다국어 리소스
~~~

Issue와 Pull Request를 환영합니다. 취약점 신고는 [SECURITY.md](SECURITY.md), 기여 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 라이선스

[MIT](LICENSE) © estelwalks contributors
