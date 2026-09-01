import { mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectPaths, detectBinary, isProjectTreeIgnoredPath, isSafeRelativePath, MAX_FILES, MAX_FILE_CONTENT_CHARS } from "../src/input.js";

describe("collectPaths", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "agent-threat-scanner-input-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("reads a single file and reports its absolute path", async () => {
    writeFileSync(join(dir, "SKILL.md"), "hello");
    const out = await collectPaths([join(dir, "SKILL.md")]);
    expect(out.files).toEqual([{ path: resolve(join(dir, "SKILL.md")), content: "hello", isBinary: false, byteSize: 5 }]);
    expect(out.excludedFiles).toEqual([]);
    expect(out.analysisPaths).toEqual([resolve(join(dir, "SKILL.md"))]);
    expect(out.singleSkillFile).toBe(true);
    expect(out.skipped).toEqual([]);
  });

  it("walks a directory and reports nested absolute paths", async () => {
    mkdirSync(join(dir, "scripts"));
    writeFileSync(join(dir, "scripts", "run.py"), "# x");
    writeFileSync(join(dir, "SKILL.md"), "# y");
    const out = await collectPaths([dir]);
    expect(out.files.map((f) => f.path).sort()).toEqual([resolve(join(dir, "SKILL.md")), resolve(join(dir, "scripts", "run.py"))]);
    expect(out.singleSkillFile).toBe(false);
  });

  it("throws for a missing path", async () => {
    await expect(collectPaths([join(dir, "nope")])).rejects.toThrow("path not found");
  });

  it("records binary and oversized files in skipped", async () => {
    writeFileSync(join(dir, "a.exe"), Buffer.from([0x4d, 0x00]));
    writeFileSync(join(dir, "big.md"), "x".repeat(MAX_FILE_CONTENT_CHARS + 1));
    const out = await collectPaths([dir]);
    expect(out.files).toContainEqual({ path: resolve(join(dir, "a.exe")), content: "", isBinary: true, byteSize: 2 });
    expect(out.excludedFiles).toContainEqual({
      path: resolve(join(dir, "big.md")), content: "", isBinary: false, byteSize: MAX_FILE_CONTENT_CHARS + 1,
    });
    expect(out.skipped.map((s) => s.reason)).toContain("binary file was not scanned");
    expect(out.skipped.map((s) => s.reason)).toContain("content exceeds 2,000,000 char limit");
  });

  it("does not follow symlink files or directories", async () => {
    const outside = mkdtempSync(join(tmpdir(), "agent-threat-scanner-outside-"));
    try {
      const secret = join(outside, "secret.txt");
      writeFileSync(secret, "AKIAABCDEFGHIJKLMNOP");
      mkdirSync(join(dir, "nested"));
      writeFileSync(join(dir, "SKILL.md"), "safe");
      symlinkSync(secret, join(dir, "linked.txt"));
      symlinkSync(outside, join(dir, "linked-dir"), "dir");

      const out = await collectPaths([dir]);
      expect(out.files.map((file) => file.path)).not.toContain(resolve(secret));
      expect(out.files.map((file) => file.content)).not.toContain("AKIAABCDEFGHIJKLMNOP");
      expect(out.skipped).toEqual(expect.arrayContaining([
        { path: resolve(join(dir, "linked.txt")), reason: "symbolic link was not scanned" },
        { path: resolve(join(dir, "linked-dir")), reason: "symbolic link was not scanned" },
      ]));
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("reports a symlink scan entry as skipped without reading its target", async () => {
    const outside = mkdtempSync(join(tmpdir(), "agent-threat-scanner-outside-entry-"));
    try {
      const secret = join(outside, "secret.txt");
      writeFileSync(secret, "AKIAABCDEFGHIJKLMNOP");
      const entry = join(dir, "entry.txt");
      symlinkSync(secret, entry);
      const out = await collectPaths([entry]);
      expect(out.files).toEqual([]);
      expect(out.excludedFiles).toEqual([]);
      expect(out.skipped).toEqual([{ path: resolve(entry), reason: "symbolic link was not scanned" }]);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("bounds reads of sparse files larger than the content cap", async () => {
    const sparse = join(dir, "sparse.bin");
    writeFileSync(sparse, "");
    truncateSync(sparse, MAX_FILE_CONTENT_CHARS * 4 + 1);
    const out = await collectPaths([sparse]);
    expect(out.files).toHaveLength(1);
    expect(out.files[0]).toMatchObject({ path: resolve(sparse), byteSize: MAX_FILE_CONTENT_CHARS * 4 + 1 });
    expect(out.skipped).toContainEqual({ path: resolve(sparse), reason: "binary file was not scanned" });
  });

  it.skipIf(process.platform === "win32")("reports special files as skipped without opening them", async () => {
    const out = await collectPaths(["/dev/null"]);
    expect(out.files).toEqual([]);
    expect(out.skipped).toContainEqual({ path: "/dev/null", reason: "special file was not scanned" });
  });

  it("skips duplicate paths passed more than once", async () => {
    const file = join(dir, "SKILL.md");
    writeFileSync(file, "a");
    const out = await collectPaths([file, file]);
    expect(out.files).toHaveLength(1);
    expect(out.skipped).toContainEqual({ path: resolve(file), reason: "duplicate path" });
  });

  it("throws when more than MAX_FILES files are collected", async () => {
    for (let i = 0; i < MAX_FILES + 1; i++) writeFileSync(join(dir, `f${i}.txt`), "x");
    await expect(collectPaths([dir])).rejects.toThrow("too many files");
  });

  it("throws when nothing is found", async () => {
    const empty = join(dir, "empty");
    mkdirSync(empty);
    await expect(collectPaths([empty])).rejects.toThrow("no files found");
  });
});

describe("binary detection", () => {
  it("checks only the first 1024 bytes for NUL bytes", () => {
    expect(detectBinary(Buffer.from([0x61, 0x00]))).toBe(true);
    expect(detectBinary(Buffer.concat([Buffer.alloc(1024, 0x61), Buffer.from([0x00])]))).toBe(false);
  });

  it("uses the configured greater-than-30-percent non-text threshold", () => {
    expect(detectBinary(Buffer.from([1, 2, 3, 65, 65, 65, 65, 65, 65, 65]))).toBe(false);
    expect(detectBinary(Buffer.from([1, 2, 3, 4, 65, 65, 65, 65, 65, 65]))).toBe(true);
    expect(detectBinary(Buffer.from([7, 8, 9, 10, 12, 13, 27, 0x20, 0x80, 0xff]))).toBe(false);
  });

  it("matches the project-tree ignore names and glob suffixes", () => {
    for (const path of ["tests/run.py", "node_modules/pkg/a.js", "build/out.js", ".env", "logs/a.log", "native/a.so", ".github/workflows/a.yml"]) {
      expect(isProjectTreeIgnoredPath(path), path).toBe(true);
    }
    for (const path of ["scripts/run.py", "references/testing.md", "builder/out.js", "env/example.txt"]) {
      expect(isProjectTreeIgnoredPath(path), path).toBe(false);
    }
  });
});

describe("isSafeRelativePath", () => {
  it("accepts clean relative paths and rejects unsafe shapes", () => {
    expect(isSafeRelativePath("SKILL.md")).toBe(true);
    expect(isSafeRelativePath("scripts/run.py")).toBe(true);
    expect(isSafeRelativePath("")).toBe(false);
    expect(isSafeRelativePath("../a")).toBe(false);
    expect(isSafeRelativePath("/a")).toBe(false);
    expect(isSafeRelativePath("a\\b")).toBe(false);
    expect(isSafeRelativePath("a/../b")).toBe(false);
    expect(isSafeRelativePath("C:/a")).toBe(false);
  });
});
