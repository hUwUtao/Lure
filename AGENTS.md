# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the main binary and core modules (config, connection, router, telemetry, threat, etc.).
- `net/` is a workspace member crate for Minecraft protocol primitives and networking helpers.
- `assets/` holds images and docs media used by README and docs.
- `settings.toml` is the default runtime configuration; the binary will create it if missing.
- `target/` is Cargo build output (do not commit).

## Build, Test, and Development Commands
- `cargo build` — compile the workspace in debug mode.
- `cargo run` — run the proxy; reads `settings.toml` from the current directory.
- `cargo run --release` — optimized build for local perf checks.
- `cargo test` — run unit tests embedded in modules (e.g., router, packet, threat).
- `cargo fmt` — format code (project uses rustfmt nightly settings).

## Coding Style & Naming Conventions
- Indentation: 4 spaces, max line length 100 (see `.editorconfig`).
- Rust formatting: `rustfmt` with crate-level import grouping (`.rustfmt.toml`).
- Modules and files: snake_case; types and traits: UpperCamelCase; consts: SCREAMING_SNAKE_CASE.

## Testing Guidelines
- Tests are inline Rust unit tests under `src/` using `#[test]`.
- Prefer naming tests after behavior (e.g., `parses_destination_with_port`).
- Run all tests with `cargo test` before submitting changes that affect routing or protocol logic.

## Commit & Pull Request Guidelines
- Recent commits use short, direct subjects (often lowercase), e.g., `rebuild for proto change`.
- `[stable]` prefix appears for release/hotfix commits; follow that pattern when applicable.
- PRs should include: a clear summary, linked issue if any, and notes on config changes.
- Include evidence for behavior changes: test output or a brief manual verification note.

## Configuration & Ops Notes
- Runtime config: `settings.toml` in repo root; reloaded on `SIGCONT`.
- Env vars: `LURE_RPC` for backend, `LURE_PROXY_SIGNING_KEY` for signing, `OTEL_EXPORTER_OTLP_ENDPOINT` for telemetry.
