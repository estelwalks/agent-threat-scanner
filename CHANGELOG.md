# Changelog

## 0.2.0

- Single-shot behavioral-analysis fast path for multi-file full scans: when every analyzed file's content fits the model budget (half the declared context window; conservative 32K chars when none is declared), the pro model analyzes the full content in ONE request instead of running the multi-turn tool-using agent. Oversized inputs keep the bounded agent loop (list_files / read_file / grep) with its single-shot fallback, so detection coverage is unchanged while full scans of large Skill libraries need far fewer LLM round-trips per Skill.
- Development-mode install/use documentation added to all four READMEs (npm link / local tarball / direct dist sync; running the CLI and the full-scan driver straight from the build output).
- Full-scan routing description updated in all four READMEs.
- Verified against a real model on a 14-Skill library: every small multi-file Skill took the single-shot route and clean Skills produced no false positives; 309 unit tests pass, typecheck and lint clean.

## 0.1.0

- Initial public release.
