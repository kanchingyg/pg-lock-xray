import { readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

import { classifyStatement, fileLevelFindings, type StatementFinding } from "./lock-rules.js";
import {
  readContainedSqlFile,
  relativeProjectPath,
  resolveContainedSqlPath,
} from "./sql-path.js";
import { rewriteSqlDocument, unifiedDiff } from "./zero-downtime-rewriter.js";

export type AnalysisReport = {
  source: string;
  statements: StatementFinding[];
  criticalCount: number;
  rewritten?: string;
  diff?: string;
};

export function splitSqlStatements(sql: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    if (c === '"' && !inSingle) inDouble = !inDouble;
    if (c === ";" && !inSingle && !inDouble) {
      const piece = cur.trim();
      if (piece) out.push(piece);
      cur = "";
      continue;
    }
    cur += c;
  }
  const tail = cur.trim();
  if (tail) out.push(tail);
  return out;
}

export function analyzeSqlText(sql: string, source = "inline"): AnalysisReport {
  const stmts = splitSqlStatements(sql);
  const statements = [
    ...fileLevelFindings(sql),
    ...stmts.map((s) => classifyStatement(s)),
  ];
  const criticalCount = statements.filter((s) => s.severity === "CRITICAL").length;
  return { source, statements, criticalCount };
}

export type ResolvedSqlInput = {
  sql: string;
  source: string;
  contentHash?: string;
};

export function resolveSqlInput(sqlOrPath: string, cwd = process.cwd()): ResolvedSqlInput {
  const looksLikeSql =
    sqlOrPath.includes("\n") ||
    /^\s*(CREATE|ALTER|DROP|SET|INSERT|UPDATE|DELETE)\b/i.test(sqlOrPath);
  if (looksLikeSql) return { sql: sqlOrPath, source: "inline" };
  const resolvedPath = resolveContainedSqlPath(sqlOrPath, cwd);
  const { sql, contentHash } = readContainedSqlFile(resolvedPath);
  return { sql, source: sqlOrPath, contentHash };
}

export function collectSqlFiles(targetDir: string): string[] {
  const st = statSync(targetDir);
  if (st.isFile()) return extname(targetDir).toLowerCase() === ".sql" ? [targetDir] : [];
  const files: string[] = [];
  for (const entry of readdirSync(targetDir, { withFileTypes: true })) {
    const full = join(targetDir, entry.name);
    if (entry.isDirectory()) files.push(...collectSqlFiles(full));
    else if (entry.isFile() && extname(entry.name).toLowerCase() === ".sql") files.push(full);
  }
  return files;
}

export function analyzeTarget(target: string, cwd = process.cwd()): AnalysisReport[] {
  const resolvedTarget = resolveContainedSqlPath(target, cwd);
  const st = statSync(resolvedTarget);
  if (st.isFile()) {
    const { sql, source } = resolveSqlInput(target, cwd);
    return [analyzeSqlText(sql, source)];
  }
  return collectSqlFiles(resolvedTarget).map((f) => {
    const { sql } = readContainedSqlFile(f);
    return analyzeSqlText(sql, relativeProjectPath(f, cwd));
  });
}

export function buildFixPreview(sql: string, label?: string): { rewritten: string; diff: string } {
  const rewritten = rewriteSqlDocument(sql);
  const diff = unifiedDiff(sql.trimEnd(), rewritten.trimEnd(), label ?? "migration.sql");
  return { rewritten, diff };
}
