# pg-lock-xray

[![ci](https://github.com/kanchingyg/pg-lock-xray/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchingyg/pg-lock-xray/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/pg-lock-xray/latest?label=npm)](https://www.npmjs.com/package/pg-lock-xray)
[![JSR](https://jsr.io/badges/@kanchingyg/pg-lock-xray)](https://jsr.io/@kanchingyg/pg-lock-xray)
[![JSR Score](https://jsr.io/badges/@kanchingyg/pg-lock-xray/score)](https://jsr.io/@kanchingyg/pg-lock-xray/score)
[![Rust](https://img.shields.io/badge/engine-Rust_%2B_TypeScript-dea584)](https://github.com/kanchingyg/pg-lock-xray)
[![license](https://img.shields.io/github/license/kanchingyg/pg-lock-xray)](https://github.com/kanchingyg/pg-lock-xray/blob/HEAD/LICENSE)
[![npm](https://img.shields.io/npm/v/pg-lock-xray)](https://www.npmjs.com/package/pg-lock-xray)
[![JSR](https://jsr.io/badges/@kanchingyg/pg-lock-xray)](https://jsr.io/@kanchingyg/pg-lock-xray)
[![Rust](https://img.shields.io/badge/engine-Rust-dea584)](https://github.com/kanchingyg/pg-lock-xray)
[![license](https://img.shields.io/github/license/kanchingyg/pg-lock-xray)](https://github.com/kanchingyg/pg-lock-xray/blob/HEAD/LICENSE)

**One line:** `npx pg-lock-xray prisma/migrations` (or `bunx pg-lock-xray prisma/migrations`): catch `ACCESS EXCLUSIVE` PostgreSQL migration lock hazards before production.

```text
+-------------------------------------------------------------+
|  migration.sql  -->  lock classifier  -->  severity report   |
|       |                      |                               |
|       +---- --fix --> CONCURRENTLY / NOT VALID rewrites      |
+-------------------------------------------------------------+
```

## Install

[Bun](https://bun.sh) / [npm](https://www.npmjs.com/package/pg-lock-xray):

```bash
bunx pg-lock-xray ./migrations
npx pg-lock-xray ./migrations

# or install in your project / globally
bun add -d pg-lock-xray
npm i -D pg-lock-xray
```

[JSR](https://jsr.io/@kanchingyg/pg-lock-xray):

```bash
bunx jsr add @kanchingyg/pg-lock-xray
npx jsr add @kanchingyg/pg-lock-xray
```

[Cargo (Rust native binary)](https://github.com/kanchingyg/pg-lock-xray):

```bash
cargo install --git https://github.com/kanchingyg/pg-lock-xray
```

The core engine is **Rust** (`src/lib.rs`, `src/main.rs`, `src/mcp.rs`): static lock rules, zero-downtime rewrite hints, and `sqlOrPath` containment under `migrations/`, `prisma/`, `supabase/`, or `sql/`. TypeScript under `src/*.ts` is included for `npx` / `bunx` / JSR usage and MCP bridge helpers.

## Quick start

```bash
npx pg-lock-xray ./migrations
bunx pg-lock-xray ./migrations
npx pg-lock-xray --fix ./sql/0001_init.sql --dry-run
npx pg-lock-xray --fix ./sql/0001_init.sql --allow-write
npx pg-lock-xray --mcp
```

## What it catches

| Pattern | Risk |
| --- | --- |
| `CREATE INDEX` without `CONCURRENTLY` | `ACCESS EXCLUSIVE` lock blocking writes |
| `CREATE INDEX USING hnsw` without `CONCURRENTLY` | pgvector blocking index build |
| `ADD CONSTRAINT ... FOREIGN KEY` without `NOT VALID` | Long table validation lock |
| Volatile `DEFAULT` on `ADD COLUMN` | Full table rewrite |

## MCP & Ollama

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "pg-lock-xray": {
      "command": "npx",
      "args": ["-y", "pg-lock-xray", "--mcp"]
    }
  }
}
```

Call MCP tool `rewrite_zero_downtime` with `{ "sqlOrPath": "...", "model": "llama3.2", "baseUrl": "http://127.0.0.1:11434" }`.

## Flags

| Flag | Purpose |
| --- | --- |
| `--allow-write` | Enable `rewrite_zero_downtime` file writes |
| `--dry-run` | Show diff / run tools without writing |
| `--mcp` | JSON-RPC MCP server on stdio |
| `--wsl-paths` | Normalize paths for WSL agents |

## MCP Tools Reference

| Tool | Mutates | Description |
| --- | --- | --- |
| `scan_sql_locks` | `false` | Analyze SQL migration files or directories and classify `ACCESS EXCLUSIVE`, `SHARE`, and table-rewrite lock hazards. |
| `rewrite_zero_downtime` | `true` | Rewrite blocking DDL statements into `CONCURRENTLY` and `NOT VALID` zero-downtime patterns (writes require `--allow-write`). |
| `explain_lock_hazard` | `false` | Return lock mode matrix details and blocked query types for a specific PostgreSQL DDL statement. |

## Editor and Agent Integration

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "pg-lock-xray": {
      "command": "npx",
      "args": ["-y", "pg-lock-xray", "--mcp"]
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add pg-lock-xray -- npx -y pg-lock-xray --mcp
```

### Programmatic Usage (JSR / TypeScript)

```ts
import * as bridge from "jsr:@kanchingyg/pg-lock-xray/bridge";
```

## Runtime Safety and Guardrails

- **Stdio frame isolation**: When `--mcp` is active, `hijackStdoutForMcp()` redirects accidental `console.log` calls to `stderr` so JSON-RPC 2.0 frames on `stdout` never corrupt.
- **Read-only by default**: Mutating tools (`mutates: true`) are blocked in `--dry-run` mode and require explicit `--allow-write` authorization.
- **Loop breaker**: Repeated identical `(toolName, args)` invocations are hashed with SHA-256 and halted after 3 consecutive repeats to prevent runaway agent loops.
- **Context budget truncation**: Tool outputs are middle-truncated (`60%` head / `40%` tail) scaled to the probed local model `n_ctx` (Ollama `/api/show`, llama.cpp `/props`, vLLM `/v1/models`).
- **Secret redaction and path normalization**: AWS keys (`AKIA*`, `ASIA*`), bearer tokens, and `sk-*` keys are scrubbed before returning tool output, and Windows drive paths (`C:\...`) translate cleanly to `/mnt/c/...` when WSL mode is enabled.

## License

[MIT](./LICENSE)
