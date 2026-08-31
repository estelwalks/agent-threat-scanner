import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync, readdirSync, realpathSync, statSync, type Stats } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import type { ScanSkillReport, SkillFile } from "./types.js";

/** Mirrors ScanSkillRequestSchema `files` max length. */
export const MAX_FILES = 500;
/** Mirrors SkillFileSchema `content` max length. */
export const MAX_FILE_CONTENT_CHARS = 2_000_000;
/** UTF-8 can use at most four bytes per decoded character; this bounds pre-read memory. */
const MAX_FILE_CONTENT_BYTES = MAX_FILE_CONTENT_CHARS * 4;

export interface CollectedInput {
  files: SkillFile[];
  /** Files excluded from content scanning but retained for file-level size/count checks. */
  excludedFiles: SkillFile[];
  /** Absolute paths visible to the scanned project tree and therefore to rules/models. */
  analysisPaths: string[];
  /** Route decision: a directory entry other than the sole SKILL.md makes this false. */
  singleSkillFile: boolean;
  /** Lexical roots used to derive a relative, model-safe path view. */
  modelRoots: string[];
  skipped: ScanSkillReport["skippedFiles"];
}

const PROJECT_TREE_IGNORED_NAMES = new Set([
  "__pycache__", "node_modules", ".env", "dist", "build", "__init__.py", "test", "tests", ".git", ".github",
  "pyproject.toml", "LICENSE", "Dockerfile", ".DS_Store", "Thumbs.db",
]);
const PROJECT_TREE_IGNORED_SUFFIXES = [".log", ".pyc", ".pyo", ".so", ".dll", ".tmp"];

export function isProjectTreeIgnoredName(name: string): boolean {
  return PROJECT_TREE_IGNORED_NAMES.has(name) || PROJECT_TREE_IGNORED_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

export function isProjectTreeIgnoredPath(path: string): boolean {
  return path.split("/").some((part) => isProjectTreeIgnoredName(part));
}

/** Rejects the same unsafe shapes as `scanner.ts`'s `safePath` so the library never sees an invalid report path. */
export function isSafeRelativePath(p: string): boolean {
  return p.length > 0 && !p.includes("\0") && !p.includes("\\") && !p.startsWith("/") && !/^[A-Za-z]:/.test(p) && !p.split("/").some((part) => !part || part === "." || part === "..");
}

/** Like `isSafeRelativePath`, but also accepts absolute POSIX paths (leading `/`); rejects NUL, backslashes, drive letters, `..`, and empty segments. */
export function isSafePath(p: string): boolean {
  if (!p || p.includes("\0") || p.includes("\\") || /^[A-Za-z]:/.test(p)) return false;
  const parts = p.split("/");
  for (let i = parts[0] === "" ? 1 : 0; i < parts.length; i++) {
    const part = parts[i];
    if (!part || part === "." || part === "..") return false;
  }
  return true;
}

export function detectBinary(buf: Buffer): boolean {
  const chunk = buf.subarray(0, 1024);
  if (chunk.includes(0)) return true;
  if (chunk.length === 0) return false;
  let nonText = 0;
  for (const byte of chunk) {
    const text = byte === 7 || byte === 8 || byte === 9 || byte === 10 || byte === 12 || byte === 13 || byte === 27 || (byte >= 0x20 && byte !== 0x7f);
    if (!text) nonText += 1;
  }
  return nonText / chunk.length > 0.3;
}

interface WalkedFile { path: string; analysisVisible: boolean; skippedReason?: string }

function walk(dir: string, ignored = false): WalkedFile[] {
  const out: WalkedFile[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    const analysisVisible = !ignored && !isProjectTreeIgnoredName(ent.name);
    // Never descend through or read a symlink. Apart from being an explicit policy,
    // this prevents a directory entry from escaping the caller's scan root.
    if (ent.isSymbolicLink()) out.push({ path: p, analysisVisible: false, skippedReason: "symbolic link was not scanned" });
    else if (ent.isDirectory()) out.push(...walk(p, !analysisVisible));
    else out.push({ path: p, analysisVisible });
  }
  return out;
}

function isWithinRoot(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
}

function noFollowFlags(): number {
  // O_NOFOLLOW is available on POSIX. lstat below remains the primary check on
  // platforms without the flag, while using it closes the path-swap race on POSIX.
  return constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
}

function readPrefix(path: string, size: number): Buffer {
  const fd = openSync(path, noFollowFlags());
  try {
    const buffer = Buffer.alloc(Math.min(size, 1024));
    const bytes = readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytes);
  } finally {
    closeSync(fd);
  }
}

function readRegularFile(path: string): Buffer {
  const fd = openSync(path, noFollowFlags());
  try {
    // fstat after opening ensures a path swapped between lstat and open cannot
    // turn into a special file or a symlink-backed read.
    const opened = fstatSync(fd);
    if (!opened.isFile()) throw new Error("not a regular file");
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Reads file or directory paths from disk into the in-memory `files` contract.
 * Report paths are resolved to absolute disk paths. Binary, oversized and unsafe paths are
 * collected in `skipped` (never thrown) so the report can surface them as `partial`;
 * missing targets, too many files and empty scans throw.
 */
export async function collectPaths(paths: string[]): Promise<CollectedInput> {
  const files: SkillFile[] = [];
  const excludedFiles: SkillFile[] = [];
  const analysisPaths: string[] = [];
  const modelRoots: string[] = [];
  const skipped: ScanSkillReport["skippedFiles"] = [];
  const seen = new Set<string>();
  let singleSkillFile = paths.length === 1;
  for (const target of paths) {
    let st: Stats;
    let targetLstat: Stats;
    try { targetLstat = lstatSync(target); } catch { throw new Error(`path not found: ${target}`); }
    const targetReportPath = resolve(target);
    if (targetLstat.isSymbolicLink()) {
      singleSkillFile = false;
      skipped.push({ path: targetReportPath, reason: "symbolic link was not scanned" });
      continue;
    }
    try { st = statSync(target); } catch { throw new Error(`path not found: ${target}`); }
    const isDir = st.isDirectory();
    let scanRoot: string;
    try { scanRoot = realpathSync(isDir ? target : dirname(target)); } catch {
      skipped.push({ path: targetReportPath, reason: "unreadable path" });
      continue;
    }
    modelRoots.push(resolve(isDir ? target : dirname(target)));
    if (isDir) {
      const entries = readdirSync(target);
      singleSkillFile &&= entries.length === 1 && entries[0] === "SKILL.md";
    } else {
      singleSkillFile &&= basename(target) === "SKILL.md";
    }
    const list = isDir ? walk(target) : [{ path: target, analysisVisible: true }];
    for (const item of list) {
      const file = item.path;
      const reportPath = resolve(file);
      if (!isSafePath(reportPath)) { skipped.push({ path: file, reason: "unsafe path" }); continue; }
      if (item.skippedReason) { skipped.push({ path: reportPath, reason: item.skippedReason }); continue; }
      if (seen.has(reportPath)) { skipped.push({ path: reportPath, reason: "duplicate path" }); continue; }
      seen.add(reportPath);
      let fileStat: Stats;
      try { fileStat = lstatSync(file); } catch { skipped.push({ path: reportPath, reason: "unreadable file" }); continue; }
      if (fileStat.isSymbolicLink()) { skipped.push({ path: reportPath, reason: "symbolic link was not scanned" }); continue; }
      if (!fileStat.isFile()) { skipped.push({ path: reportPath, reason: "special file was not scanned" }); continue; }
      let realFilePath: string;
      try { realFilePath = realpathSync(file); } catch { skipped.push({ path: reportPath, reason: "unreadable file" }); continue; }
      if (!isWithinRoot(scanRoot, realFilePath)) { skipped.push({ path: reportPath, reason: "path escapes scan root" }); continue; }
      // Check the byte size before opening/reading. A larger byte bound is used
      // to preserve the documented character limit for multi-byte UTF-8 text.
      if (fileStat.size > MAX_FILE_CONTENT_BYTES) {
        let prefix: Buffer;
        try { prefix = readPrefix(file, 1024); } catch (error) {
          skipped.push({ path: reportPath, reason: `unreadable file: ${(error as Error).message}` });
          continue;
        }
        const binary = detectBinary(prefix);
        if (binary) {
          skipped.push({ path: reportPath, reason: "binary file was not scanned" });
          if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
          files.push({ path: reportPath, content: "", isBinary: true, byteSize: fileStat.size });
        } else {
          skipped.push({ path: reportPath, reason: "content exceeds 2,000,000 char limit" });
          if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
          excludedFiles.push({ path: reportPath, content: "", isBinary: false, byteSize: fileStat.size });
        }
        continue;
      }
      let buf: Buffer;
      try { buf = readRegularFile(file); } catch (error) { skipped.push({ path: reportPath, reason: `unreadable file: ${(error as Error).message}` }); continue; }
      if (basename(file) === ".DS_Store") {
        if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
        files.push({ path: reportPath, content: "", isBinary: false, byteSize: fileStat.size });
        continue;
      }
      if (detectBinary(buf)) {
        skipped.push({ path: reportPath, reason: "binary file was not scanned" });
        if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
        files.push({ path: reportPath, content: "", isBinary: true, byteSize: fileStat.size });
        continue;
      }
      const content = buf.toString("utf-8");
      if (content.length > MAX_FILE_CONTENT_CHARS) {
        skipped.push({ path: reportPath, reason: "content exceeds 2,000,000 char limit" });
        if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
        excludedFiles.push({ path: reportPath, content: "", isBinary: false, byteSize: fileStat.size });
        continue;
      }
      if (files.length + excludedFiles.length >= MAX_FILES) throw new Error(`too many files: ${MAX_FILES} max`);
      files.push({ path: reportPath, content, isBinary: false, byteSize: fileStat.size });
      if (item.analysisVisible) analysisPaths.push(reportPath);
    }
  }
  if (files.length === 0 && excludedFiles.length === 0 && skipped.length === 0) throw new Error("no files found");
  return { files, excludedFiles, analysisPaths, singleSkillFile, modelRoots, skipped };
}
