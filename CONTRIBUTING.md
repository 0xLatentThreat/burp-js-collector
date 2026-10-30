# Contributing to JS Collector

Thank you for considering contributing to JS Collector!

## How Can I Contribute?

### 1. Reporting Edge Cases & Bundler Samples
Modern JavaScript bundlers (Webpack, Vite, Rollup, esbuild, Turbopack) evolve constantly. If you encounter a website where endpoints or lazy chunks are missed:
1. Open an issue using the [Unparsed JS Sample Submission](.github/ISSUE_TEMPLATE/chunk_sample.md) template.
2. Provide a sanitized minimal JS snippet and the expected endpoint information.
3. We will add it directly as an automated regression test scenario under `test/scenarios/`.

### 2. Submitting Code Changes
1. Fork the repository and create your feature branch from `main`.
2. Ensure bytecode compatibility: compilation must use `--release 17`.
3. Run the stress benchmark to verify stability:
   - `StressTest`
4. **Clean Commit Requirement**:
   - Always run `git status` before committing.
   - Do **NOT** commit any binary artifacts (`.jar`, `.class`), local build outputs (`build/`, `core/out/`), IDE settings (`.idea/`, `.vscode/`), local caches (`.gradle/`), or draft notes. Keep the repository pure source-only.
5. Submit a Pull Request with a clear description of the enhancement.
