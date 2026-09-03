import { createHash } from "node:crypto";
import { basename, relative, resolve, sep } from "node:path";
import { ENGINE_VERSION, RULES_VERSION } from "./rules/index.js";
import { staticScan } from "./detection/staticScan.js";
import { fileLevelScan } from "./detection/fileChecks.js";
import { asFindings, buildCategories, buildContext, buildRuleAggregations, buildSummary } from "./detection/report.js";
import { computeScore, threatLevelOf, verdictOf } from "./detection/scoring.js";
import { dedupByLocation, semanticDedup } from "./detection/dedup.js";
import { ModelResponseSchema, RuleVerificationSchema, askModel, capFilesForModel } from "./model/client.js";
import type { BehavioralRiskItem } from "./model/client.js";
import { runBehavioralAgent } from "./model/agent.js";
import { ATTACK_PATTERNS_CONTENT, ATTACK_PATTERNS_PATH, buildModelPrompts, formatFilesForPrompt, formatFindingsForVerification } from "./model/prompts.js";
import { redact } from "./model/normalize.js";
import { TokenUsageCollector } from "./model/usage.js";
import { getMessages } from "./i18n/index.js";
import { collectPaths, isSafePath, isSafeRelativePath } from "./input.js";
import { ScanSkillReportSchema, ScanSkillRequestSchema, type Finding, type ScanDependencies, type ScanSkillReport, type SkillFile } from "./types.js";

function validateFiles(inputFiles: SkillFile[], detectContentNul = true, allowDiskPaths = false): { files: SkillFile[]; skipped: ScanSkillReport["skippedFiles"] } {
  const paths = new Set<string>(); const files: SkillFile[] = []; const skipped: ScanSkillReport["skippedFiles"] = [];
  for (const file of inputFiles) {
    if (!(allowDiskPaths ? isSafePath(file.path) : isSafeRelativePath(file.path))) throw new Error(`Invalid relative file path: ${JSON.stringify(file.path)}`);
    if (paths.has(file.path)) throw new Error(`Duplicate relative file path: ${JSON.stringify(file.path)}`);
    paths.add(file.path);
    if (file.isBinary || (detectContentNul && file.content.includes("\0"))) skipped.push({ path: file.path, reason: "binary file was not scanned" });
    else files.push(file);
  }
  return { files, skipped };
}

/** Hashes the sorted (path, content) pairs to build a language-isolated cache key. */
function contentHash(inputFiles: SkillFile[]): string {
  const hash = createHash("sha256");
  for (const file of [...inputFiles].sort((a, b) => a.path.localeCompare(b.path))) {
    hash.update(file.path).update("\0").update(file.content);
  }
  return hash.digest("hex");
}

/** Hashes a single file's (path, content) pair to build a content-addressed file identifier. */
function hashFile(file: { path: string; content: string }): string {
  const hash = createHash("sha256");
  hash.update(file.path).update("\0").update(file.content);
  return hash.digest("hex");
}

interface ModelPathView {
  files: SkillFile[];
  /** Model-relative path → report path. Undefined means the input was already in-memory. */
  modelPathToReportPath?: ReadonlyMap<string, string>;
  pathForModel: (path: string) => string;
}

function commonPath(paths: string[]): string {
  if (paths.length === 0) return resolve(".");
  const parts = paths.map((path) => resolve(path).split(sep));
  const prefix: string[] = [];
  for (let index = 0; ; index++) {
    const value = parts[0]?.[index];
    if (value === undefined || parts.some((items) => items[index] !== value)) break;
    prefix.push(value);
  }
  if (prefix.length === 0) return resolve(sep);
  // On POSIX the leading empty component represents `/`; on Windows this still
  // produces a usable absolute root for the paths accepted by collectPaths.
  const root = prefix.join(sep) || sep;
  return resolve(root);
}

/** Builds a model-only relative path view while preserving absolute report paths. */
function buildModelPathView(files: SkillFile[], modelRoots: string[], diskInput: boolean): ModelPathView {
  if (!diskInput) return { files, pathForModel: (path) => path };
  const root = commonPath(modelRoots);
  const reportToModel = new Map<string, string>();
  const modelToReport = new Map<string, string>();
  for (const file of files) {
    const modelPath = relative(root, file.path).split(sep).join("/") || basename(file.path);
    // A collision is possible only when multiple roots are identical aliases;
    // retain the first path so a model cannot select an ambiguous report path.
    if (!modelToReport.has(modelPath)) {
      modelToReport.set(modelPath, file.path);
      reportToModel.set(file.path, modelPath);
    }
  }
  return {
    files: files.map((file) => ({ ...file, path: reportToModel.get(file.path) ?? basename(file.path) })),
    modelPathToReportPath: modelToReport,
    pathForModel: (path) => path === "." ? "." : reportToModel.get(path) ?? basename(path),
  };
}

/** Scans in-memory `files` or disk `paths`; it never persists API keys or executes Skill code. */
export async function scanSkill(input: unknown, dependencies: ScanDependencies = {}): Promise<ScanSkillReport> {
  const request = ScanSkillRequestSchema.parse(input);
  const locale = request.locale;
  const messages = getMessages(locale);
  const prompts = buildModelPrompts();
  const log = dependencies.log;
  const usageCollector = new TokenUsageCollector();
  log?.(`scan:init locale=${locale} mode=${request.mode} input=${request.files ? "memory" : "disk"} model=${request.model ? "configured" : "none"}`);
  const diskInput = request.files
    ? {
        files: request.files,
        excludedFiles: [] as SkillFile[],
        analysisPaths: request.files.map((file) => file.path),
        singleSkillFile: request.files.length === 1 && !request.files[0].isBinary && basename(request.files[0].path) === "SKILL.md",
        modelRoots: [] as string[],
        skipped: [] as ScanSkillReport["skippedFiles"],
      }
      : await collectPaths(request.paths!, log);
  if (request.files) {
    for (const file of request.files) {
      log?.(`input:file loaded path=${JSON.stringify(file.path)} bytes=${Buffer.byteLength(file.content, "utf8")} chars=${file.content.length} binary=${Boolean(file.isBinary)} analysisVisible=true source=memory`);
    }
  }
  const allInputFiles = [...diskInput.files, ...diskInput.excludedFiles];
  const validated = validateFiles(diskInput.files, Boolean(request.files), Boolean(request.paths));
  const analysisPaths = new Set(diskInput.analysisPaths);
  const files = validated.files.filter((file) => analysisPaths.has(file.path));
  const modelView = buildModelPathView(files, diskInput.modelRoots, Boolean(request.paths));
  const skipped = validated.skipped;
  const allSkipped = [...new Map([...diskInput.skipped, ...skipped].map((item) => [`${item.path}\0${item.reason}`, item])).values()];
  const fileHashes = new Map<string, string>();
  for (const file of allInputFiles) fileHashes.set(file.path, hashFile(file));
  const singleSkillFile = diskInput.singleSkillFile;
  log?.(`input:complete files=${allInputFiles.length} scanned=${files.length} skipped=${allSkipped.length}${request.paths ? ` paths=${request.paths.length}` : " source=memory"}`);
  log?.(`static:init files=${files.length} locale=${locale}`);
  const staticFindings = staticScan(files, locale, fileHashes, log);
  const fileCheckFindings = fileLevelScan(allInputFiles, files, locale, fileHashes, log);
  let findings: Finding[] = [...staticFindings, ...fileCheckFindings];
  log?.(`static:complete ruleFindings=${staticFindings.length} fileCheckFindings=${fileCheckFindings.length} total=${findings.length}`);
  const branches: ScanSkillReport["branches"] = [{ name: "static", status: "complete" }]; let partial = allSkipped.length > 0;
  if (request.mode === "full") {
    if (!request.model) {
      partial = true; branches.push({ name: "ruleReview", status: "skipped", detail: "model configuration is required for full scan" }, { name: "singleFileAnalysis", status: "skipped", detail: "model configuration is required for full scan" }, { name: "multiFileAnalysis", status: "skipped", detail: "model configuration is required for full scan" });
      log?.("model:skipped reason=configuration-missing");
    } else {
      const fetcher = dependencies.fetch ?? globalThis.fetch;
      if (!fetcher) { partial = true; log?.("model: fetch is unavailable, model branches failed"); for (const name of ["ruleReview", "singleFileAnalysis", "multiFileAnalysis"] as const) branches.push({ name, status: "failed", detail: "fetch is unavailable" }); }
      else {
        log?.(`model:init provider=${request.model.provider ?? "auto"} lite=${JSON.stringify(request.model.liteModel)} pro=${JSON.stringify(request.model.proModel)} timeoutMs=${request.model.timeoutMs}`);
        // 1) ruleReview: verify each static hit individually and drop false positives; bypass hits (IOC/file-level) are kept as-is
        const bypassed = findings.filter((f) => f.bypassVerification);
        const toVerify = findings.filter((f) => !f.bypassVerification);
        log?.(`ruleReview: verifying ${toVerify.length} static hit(s)`);
        if (toVerify.length === 0) {
          branches.push({ name: "ruleReview", status: "complete" });
        } else {
          try {
            const ruleReviewList = formatFindingsForVerification(toVerify.map((f) => {
              const modelPath = modelView.pathForModel(f.path);
              return { ruleId: f.ruleId, ruleName: f.ruleName, path: modelPath, line: f.line, message: f.message, excerpt: f.excerpt, context: buildContext(modelView.files, modelPath, f.line) };
            }));
            const ruleReviewTask = `Please verify each of the following rule hits for whether it is a real risk. The context around each hit (±2 lines) is provided; no file reads are needed. Output strict JSON per the schema.\n\nHit list:\n${ruleReviewList}`;
            const veri = await askModel(fetcher, request.model, request.model.liteModel, ruleReviewTask, "", prompts.shapeVerifications, RuleVerificationSchema, prompts.ruleReview, { collector: usageCollector, context: { model: request.model.liteModel, branch: "ruleReview" }, log });
            const decisions = new Map(veri.verifications.map((item) => [item.index, item.is_true_positive]));
            findings = [...bypassed, ...toVerify.filter((_, index) => decisions.get(index) !== false)];
            log?.(`analysis:ruleReview complete responses=${veri.verifications.length} input=${toVerify.length} kept=${findings.length} dropped=${toVerify.length - toVerify.filter((_, index) => decisions.get(index) !== false).length}`);
            branches.push({ name: "ruleReview", status: "complete" });
          } catch (error) {
            partial = true; branches.push({ name: "ruleReview", status: "failed", detail: redact(error instanceof Error ? error.message : "unknown model error") });
          }
        }
        log?.(`ruleReview: ${findings.length} finding(s) after verification`);
        // 2) Dynamic route: exactly one SKILL.md uses single-file analysis; all other inputs use the behavioral agent.
        const results: Array<{ name: "singleFileAnalysis" | "multiFileAnalysis"; findings?: BehavioralRiskItem[]; error?: string }> = [];
        if (singleSkillFile) {
          branches.push({ name: "multiFileAnalysis", status: "skipped", detail: "single SKILL.md input" });
            const skillFiles = capFilesForModel(modelView.files, request.model);
          log?.(`singleFileAnalysis: analyzing ${skillFiles.length} file(s) with ${request.model.proModel}`);
          const singleTask = "Perform a behavioral security analysis of the following SKILL content to find security risks that static rules cannot detect. Output strict JSON per the schema; do not use markdown code fences.\nBelow is the content:\n\n";
          try {
            const response = await askModel(fetcher, request.model, request.model.proModel, singleTask, formatFilesForPrompt(skillFiles), prompts.shapeFindings, ModelResponseSchema, prompts.single, { collector: usageCollector, context: { model: request.model.proModel, branch: "singleFileAnalysis" }, log });
            results.push({ name: "singleFileAnalysis", findings: response.findings });
          } catch (error) {
            results.push({ name: "singleFileAnalysis", error: error instanceof Error ? error.message : "unknown model error" });
          }
        } else {
          branches.push({ name: "singleFileAnalysis", status: "skipped", detail: "multi-file input" });
          log?.(`multiFileAnalysis: running behavioral agent with ${request.model.proModel}`);
          const agentFiles: SkillFile[] = [...modelView.files, { path: ATTACK_PATTERNS_PATH, content: ATTACK_PATTERNS_CONTENT, isBinary: false }];
          const fileListJson = JSON.stringify(agentFiles.map((f) => ({ path: f.path, lineCount: f.content.split(/\r?\n/).length, chars: f.content.length })));
          const multiTask = "Perform a behavioral security analysis of the following SKILL directory content to find security risks that static rules cannot detect. Output strict JSON per the schema; do not use markdown code fences.\nBelow is the full file content:\n\n";
          try {
            let behavioralFindings: BehavioralRiskItem[];
            try {
              behavioralFindings = await runBehavioralAgent(fetcher, request.model, agentFiles, prompts.agentSystem, prompts.agentTask(fileListJson), usageCollector, log);
            } catch {
              log?.("model:multiFileAnalysis fallback=single-request");
              const response = await askModel(fetcher, request.model, request.model.proModel, multiTask, formatFilesForPrompt(capFilesForModel(modelView.files, request.model)), prompts.shapeFindings, ModelResponseSchema, prompts.multi, { collector: usageCollector, context: { model: request.model.proModel, branch: "multiFileAnalysis" }, log });
              behavioralFindings = response.findings;
            }
            results.push({ name: "multiFileAnalysis", findings: behavioralFindings });
          } catch (error) {
            results.push({ name: "multiFileAnalysis", error: error instanceof Error ? error.message : "unknown model error" });
          }
        }
        const modelFindings: Finding[] = [];
        for (const result of results) {
          if (result.error) { partial = true; branches.push({ name: result.name, status: "failed", detail: redact(result.error) }); log?.(`${result.name}: failed`); }
          else { branches.push({ name: result.name, status: "complete" }); log?.(`analysis:${result.name} normalize start modelFindings=${result.findings?.length ?? 0}`); modelFindings.push(...asFindings(result.findings ?? [], files, result.name, locale, fileHashes, modelView.modelPathToReportPath, log)); log?.(`${result.name}: ${result.findings?.length ?? 0} finding(s)`); }
        }
        // 3) Location dedup runs within each side before semantic dedup.
        log?.(`dedup:location start rules=${findings.length} model=${modelFindings.length}`);
        const locationDeduped = dedupByLocation(findings, modelFindings);
        const verifiedStatic = locationDeduped.rules;
        const modelDeduped = locationDeduped.model;
        log?.(`dedup: location dedup kept ${modelDeduped.length} of ${modelFindings.length} model finding(s)`);
        // 4) Semantic dedup compares every retained rule finding against model findings; model wins on overlap.
        const keptRules = await semanticDedup(fetcher, request.model, verifiedStatic, modelDeduped, usageCollector, modelView.pathForModel, log);
        log?.(`dedup: semantic dedup kept ${keptRules.length} of ${verifiedStatic.length} rule finding(s)`);
        findings = [...keptRules, ...modelDeduped];
      }
    }
  }
  log?.(`dedup:final start findings=${findings.length}`);
  const finalLocationDedup = dedupByLocation(findings.filter((item) => item.source === "static"), findings.filter((item) => item.source === "model"));
  findings = [...finalLocationDedup.rules, ...finalLocationDedup.model];
  log?.(`dedup:final complete rules=${finalLocationDedup.rules.length} model=${finalLocationDedup.model.length} total=${findings.length}`);
  log?.(`aggregate:start findings=${findings.length}`);
  const score = computeScore(findings); const level = threatLevelOf(score);
  const verdict = verdictOf(score, partial, findings);
  log?.(`aggregate:score riskScore=${score} threatLevel=${level} verdict=${verdict}`);
  const categories = buildCategories(findings, locale);
  const summary = buildSummary(allInputFiles.length, findings, locale);
  const rules = buildRuleAggregations(findings.filter((f) => f.source === "static"), locale);
  log?.(`aggregate:complete categories=${Object.keys(categories).length} rules=${rules.length}`);
  log?.(`summary:complete chars=${summary.length}`);
  log?.(`result: riskScore=${score} threatLevel=${level} verdict=${verdict} findings=${findings.length} status=${partial ? "partial" : "complete"}`);
  const report = {
    status: partial ? "partial" as const : "complete" as const, mode: request.mode, verdict,
    riskScore: score, rulesVersion: RULES_VERSION, engineVersion: ENGINE_VERSION,
    locale, contentHash: contentHash(allInputFiles), scannedFiles: allInputFiles.length,
    threatLevel: level, threatLevelDisplay: messages.threatLevel[level],
    categories, summary,
    findings, rules,
    branches, skippedFiles: allSkipped, tokenUsage: usageCollector.report(),
  };
  log?.(`output:report validate findings=${findings.length} skipped=${allSkipped.length}`);
  const parsedReport = ScanSkillReportSchema.parse(report);
  log?.(`output:report ready status=${parsedReport.status} tokenRequests=${parsedReport.tokenUsage.requestCount}`);
  return parsedReport;
}
