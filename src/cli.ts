#!/usr/bin/env node

import {
  setGuards,
  startMcpServer,
  callOpenAiCompatChat,
  redactSecrets,
  type McpToolDefinition,
} from "./bridge.js";
import { writeContainedSqlFile } from "./sql-path.js";
import {
  analyzeTarget,
  analyzeSqlText,
  buildFixPreview,
  resolveSqlInput,
} from "./sql-analyzer.js";
import { rewriteSqlDocument } from "./zero-downtime-rewriter.js";

const VERSION = "0.1.0";

function buildMcpTools(): McpToolDefinition[] {
  return [
    {
      name: "check_migration_locks",
      description: "Classify SQL migration statements by Postgres lock mode.",
      inputSchema: {
        type: "object",
        properties: { sqlOrPath: { type: "string" } },
        required: ["sqlOrPath"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      handler: (args) => {
        const input = String(args.sqlOrPath);
        const { sql, source } = resolveSqlInput(input);
        const report = analyzeSqlText(sql, source);
        return report;
      },
    },
    {
      name: "rewrite_zero_downtime",
      description: "Rewrite risky migration SQL into expand/contract steps.",
      inputSchema: {
        type: "object",
        properties: {
          sqlOrPath: { type: "string" },
          model: { type: "string" },
          baseUrl: { type: "string" },
        },
        required: ["sqlOrPath"],
        additionalProperties: false,
      },
      annotations: { destructiveHint: true },
      mutates: true,
      handler: async (args, ctx) => {
        const { sql, source, contentHash } = resolveSqlInput(String(args.sqlOrPath));
        let rewritten = rewriteSqlDocument(sql);
        const model = args.model ? String(args.model) : undefined;
        const baseUrl = args.baseUrl ? String(args.baseUrl) : process.env.OLLAMA_HOST;
        if (model && baseUrl) {
          const llm = await callOpenAiCompatChat(baseUrl, {
            model,
            messages: [
              {
                role: "user",
                content: `Improve this Postgres zero-downtime migration. Return SQL only.\n\n${redactSecrets(rewritten)}`,
              },
            ],
          });
          if (llm.trim()) rewritten = llm.trim();
        }
        const preview = buildFixPreview(sql, source);
        if (ctx.dryRun || !ctx.allowWrite) {
          return { rewritten, diff: preview.diff, wrote: false };
        }
        if (source !== "inline") {
          const path = writeContainedSqlFile(source, rewritten, {
            expectedContentHash: contentHash,
          });
          return { rewritten, diff: preview.diff, wrote: true, path };
        }
        return { rewritten, diff: preview.diff, wrote: false };
      },
    },
  ];
}

export async function runCli(argv: string[]): Promise<number> {
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const rest = argv.filter((a) => !a.startsWith("--"));

  if (flags.has("--dry-run")) setGuards({ dryRun: true });
  if (flags.has("--allow-write")) setGuards({ allowWrite: true });

  if (flags.has("--mcp")) {
    startMcpServer(
      { name: "pg-lock-xray", version: VERSION },
      buildMcpTools(),
      { allowWrite: flags.has("--allow-write"), pathToWsl: flags.has("--wsl-paths") },
    );
    return 0;
  }

  const fixMode = flags.has("--fix");
  const target = rest[0];

  if (!target) {
    process.stderr.write(
      "Usage: pg-lock-xray <dir-or.sql> | pg-lock-xray --fix <file.sql> [--dry-run] [--allow-write] | pg-lock-xray --mcp\n",
    );
    return 2;
  }

  try {
    if (fixMode) {
      const { sql, source, contentHash } = resolveSqlInput(target);
      const { rewritten, diff } = buildFixPreview(sql, source);
      if (flags.has("--dry-run") || !flags.has("--allow-write")) {
        process.stdout.write(`${diff}\n`);
        return 0;
      }
      if (source === "inline") {
        process.stderr.write("Cannot write inline SQL; pass a file path.\n");
        return 2;
      }
      writeContainedSqlFile(source, rewritten, { expectedContentHash: contentHash });
      process.stdout.write(`Rewrote ${source}\n`);
      return 0;
    }

    const reports = analyzeTarget(target);
    for (const r of reports) {
      process.stdout.write(`\n# ${r.source} (${r.criticalCount} critical)\n`);
      for (const s of r.statements) {
        if (s.statement === "(file)" && s.risks.length === 0) continue;
        process.stdout.write(
          `[${s.severity}] ${s.lockMode} — ${s.message}\n  ${s.statement.slice(0, 120)}\n`,
        );
      }
    }
    const totalCritical = reports.reduce((n, r) => n + r.criticalCount, 0);
    return totalCritical > 0 ? 1 : 0;
  } catch (e) {
    process.stderr.write(String(e) + "\n");
    return 1;
  }
}

const isMain = process.argv[1]?.includes("cli");
if (isMain) {
  void runCli(process.argv.slice(2)).then((code) => {
    if (!process.argv.includes("--mcp")) process.exit(code);
  });
}
