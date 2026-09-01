import { createRequire } from "node:module";
import { scanSkill } from "../index.js";
import type { FetchLike } from "../types.js";
import { parseArgs, UsageError } from "./args.js";
import { loadConfig, loadDotEnv } from "./config.js";
import { renderJson, renderSummary, writeOutput } from "./output.js";

const USAGE = `Usage: agent-threat-scan <file-or-directory> [options]

Scan an agent artifact file or directory (quick static scan, or full scan with model review).

Options:
  --config <file>               JSON config file (default: ./.agent-threat-scanner.json)
  --mode <quick|full>           scan mode (default: full if a model is configured, else quick)
  --quick                       static-only scan (same as --mode quick)
  --locale <locale>             zh-CN | en-US | ja-JP | ko-KR (default: zh-CN)
  --provider <openai-responses|openai-completions|anthropic>
                                LLM protocol (legacy openai maps to openai-completions)
  --endpoint <url>              LLM base URL
  --lite-model <name>           model for rule verification + semantic dedup
  --pro-model <name>            model for single/cross-file behavioral analysis
  --timeout-ms <ms>             per-call model timeout (default: 120000)
  --context-window-tokens <n>   model context window in tokens
  --max-agent-turns <n>         behavioral agent tool-call turns (default: 12)
  --json                        output the full JSON report
  --output <file>               write the report to a file
  --verbose                     verbose scan logging to stderr
  -h, --help                    show this help
  -v, --version                 show version

Config precedence: CLI flags > config file > LLM_* environment variables.
`;

export interface MainIO {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  fetch?: FetchLike;
}

/** Replaces configured credentials in user-visible CLI text without changing the report object. */
function redactSecrets(value: string, secrets: Iterable<string>): string {
  let redacted = value;
  for (const secret of secrets) {
    if (secret.length > 0) redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted;
}

function errorText(error: unknown, secrets: Iterable<string>): string {
  return redactSecrets(error instanceof Error ? error.message : String(error), secrets);
}

export async function main(argv: string[], io: MainIO = {}): Promise<number> {
  let args;
  try { args = parseArgs(argv); }
  catch (error) {
    if (error instanceof UsageError) { console.error(`error: ${error.message}`); console.error("Run 'agent-threat-scan --help' for usage."); return 1; }
    throw error;
  }
  if (args.help) { console.log(USAGE); return 0; }
  if (args.version) { console.log(packageVersion()); return 0; }
  if (args.positional === undefined) { console.error("error: missing path argument"); console.error("Run 'agent-threat-scan --help' for usage."); return 1; }

  const cwd = io.cwd ?? process.cwd();
  const env = { ...(io.env ?? process.env) };
  const secrets = new Set<string>();
  if (env.LLM_API_KEY) secrets.add(env.LLM_API_KEY);
  const verboseRequested = args.verbose;
  const verboseLog = (message: string): void => {
    // Keep diagnostics useful while ensuring a future log field cannot echo a configured credential.
    console.error(`[agent-threat-scan] ${redactSecrets(message, secrets)}`);
  };
  if (verboseRequested) verboseLog(`config:init start cwd=${JSON.stringify(cwd)} config=${JSON.stringify(args.config ?? "./.agent-threat-scanner.json")}`);
  const dotenvLoaded = loadDotEnv(env, cwd);
  if (verboseRequested) verboseLog(`config:dotenv loaded=${dotenvLoaded}`);
  if (env.LLM_API_KEY) secrets.add(env.LLM_API_KEY);
  let config;
  try { config = loadConfig(args, env, cwd); }
  catch (error) { console.error(`error: ${errorText(error, secrets)}`); return 1; }
  if (config.model?.apiKey) secrets.add(config.model.apiKey);

  if (args.verbose) {
    verboseLog(`config:resolved mode=${config.mode} locale=${config.locale}${config.model ? ` provider=${config.model.provider ?? "auto"} lite=${JSON.stringify(config.model.liteModel)} pro=${JSON.stringify(config.model.proModel)} timeoutMs=${config.model.timeoutMs}` : " model=none"}`);
  }
  if (config.mode === "quick" && !config.modeExplicit) {
    console.error("LLM model not fully configured (endpoint/apiKey/liteModel/proModel); running STATIC-ONLY quick scan.");
  }
  console.error(`Scanning ${args.positional} (${config.mode}${config.model ? "" : " static-only"})...`);
  if (args.verbose) verboseLog(`scan:start target=${JSON.stringify(args.positional)} mode=${config.mode}`);

  let report;
  const started = performance.now();
  try {
    report = await scanSkill({ mode: config.mode, locale: config.locale, paths: [args.positional], ...(config.model ? { model: config.model } : {}) }, {
      ...(io.fetch ? { fetch: io.fetch } : {}),
      ...(args.verbose ? { log: verboseLog } : {}),
    });
  } catch (error) {
    console.error(`error: ${errorText(error, secrets)}`);
    return 1;
  }
  if (args.verbose) verboseLog(`scan:complete elapsedMs=${Math.round(performance.now() - started)}`);

  if (args.verbose) verboseLog(`output:start format=${args.json ? "json" : "summary"} destination=${args.output ? "file" : "stdout"}`);
  if (args.verbose) verboseLog("output:render start");
  const text = redactSecrets(args.json ? renderJson(report) : renderSummary(report), secrets);
  if (args.verbose) verboseLog(`output:render complete chars=${text.length}`);
  if (args.output) {
    try { writeOutput(args.output, text); } catch (error) { console.error(`error: ${errorText(error, secrets)}`); return 1; }
    if (args.verbose) verboseLog(`output:complete destination=file path=${JSON.stringify(args.output)} chars=${text.length}`);
    console.error(`Report written to ${args.output}`);
  } else {
    console.log(text);
    if (args.verbose) verboseLog(`output:complete destination=stdout chars=${text.length}`);
  }
  return 0;
}

const VERSION_FALLBACK = "0.0.0";

function packageVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    return require("../package.json").version as string;
  } catch { return VERSION_FALLBACK; }
}
