# pg-lock-xray

**One line:** `npx pg-lock-xray prisma/migrations` — catch `ACCESS EXCLUSIVE` migration traps before prod.

```
┌─────────────────────────────────────────────────────────────┐
│  migration.sql  ──►  lock classifier  ──►  severity report   │
│       │                      │                               │
│       └──── --fix ──► CONCURRENTLY / NOT VALID rewrites      │
└─────────────────────────────────────────────────────────────┘
```

## Install

```bash
npx pg-lock-xray ./migrations          # Node wrapper (native Rust if built, else vendored TS)
cargo install --path .                 # native CLI on PATH as `pg-lock-xray`
```

The core engine is **Rust** (`src/lib.rs`, `src/main.rs`, `src/mcp.rs`) — static lock rules, zero-downtime rewrite hints, and `sqlOrPath` containment under `migrations/`, `prisma/`, `supabase/`, or `sql/`. TypeScript under `src/*.ts` is vendored for `npx` fallback and MCP bridge helpers (LLM adapters).

## Quick start

```bash
npx pg-lock-xray ./migrations
npx pg-lock-xray --fix ./sql/0001_init.sql --dry-run
npx pg-lock-xray --fix ./sql/0001_init.sql --allow-write
npx pg-lock-xray --mcp
```

```bash
cargo run -- ./migrations
cargo run -- --fix sql/0001_init.sql --dry-run
cargo run -- --mcp --allow-write
```

## What it catches

| Pattern | Risk |
|---------|------|
| `CREATE INDEX` without `CONCURRENTLY` | `ACCESS EXCLUSIVE` |
| `CREATE INDEX USING hnsw` without `CONCURRENTLY` | pgvector blocking build |
| `ADD CONSTRAINT … FOREIGN KEY` without `NOT VALID` | long validation lock |
| Volatile `DEFAULT` on `ADD COLUMN` | table rewrite |

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

For local models (Ollama, LM Studio, vLLM OpenAI-compatible) use the **Node** fallback path or set `PG_LOCK_XRAY_BIN` to a Rust binary; optional LLM polish on `rewrite_zero_downtime` is implemented in the vendored TS bridge.

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
```

Call MCP tool `rewrite_zero_downtime` with `{ "sqlOrPath": "...", "model": "llama3.2", "baseUrl": "http://127.0.0.1:11434" }`.

## Flags

| Flag | Purpose |
| --- | --- |
| `--allow-write` | Enable `rewrite_zero_downtime` file writes |
| `--dry-run` | Show diff / run tools without writing |
| `--mcp` | JSON-RPC MCP server on stdio |
| `--wsl-paths` | Normalize paths for WSL agents (Node fallback) |

## License

MIT
