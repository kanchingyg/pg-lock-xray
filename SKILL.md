---
name: pg-lock-xray
description: Scan Prisma/Drizzle/raw SQL migrations for Postgres lock risk and zero-downtime rewrites.
---

# pg-lock-xray

## When to use

- Before applying Prisma, Drizzle, or raw `.sql` migrations in production.
- You need per-statement lock modes (`ACCESS EXCLUSIVE`, `SHARE UPDATE EXCLUSIVE`, etc.).
- You want automatic expand/contract rewrites (`CONCURRENTLY`, `NOT VALID` + `VALIDATE`).

## Commands

```bash
npx pg-lock-xray prisma/migrations
npx pg-lock-xray --fix ./drizzle/0001.sql --dry-run
npx pg-lock-xray --fix ./migration.sql --allow-write
npx pg-lock-xray --mcp
```

## MCP tools (`--mcp`)

| Tool | Purpose |
|------|---------|
| `check_migration_locks` | Lock mode + severity per SQL statement |
| `rewrite_zero_downtime` | Deterministic rewrite; optional local model via `model` + `baseUrl` |

## Flags

- `--dry-run`  -  show unified diff; MCP mutating tools simulate only
- `--allow-write`  -  allow `--fix` and `rewrite_zero_downtime` to write files
- `--wsl-paths`  -  normalize Windows ↔ WSL paths in MCP I/O

## Cursor config snippet

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

## Ollama / local models

Set `OLLAMA_HOST=http://127.0.0.1:11434` and pass `model` to `rewrite_zero_downtime` for optional LLM polish after deterministic rules.
