import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const SQL_PATH_ALLOWLIST_PREFIXES = [
  "migrations/",
  "prisma/",
  "supabase/",
  "sql/",
] as const;

export const MAX_SQL_FILE_BYTES = 2 * 1024 * 1024;

function normalizeRelPath(input: string): string {
  return input.replace(/\\/g, "/");
}

function isUnderAllowlistedPrefix(relPath: string): boolean {
  const norm = normalizeRelPath(relPath);
  return SQL_PATH_ALLOWLIST_PREFIXES.some(
    (prefix) => norm === prefix.slice(0, -1) || norm.startsWith(prefix),
  );
}

export function projectRootReal(cwd: string): string {
  const base = resolve(cwd);
  try {
    return realpathSync.native(base);
  } catch {
    return base;
  }
}

function assertRelativeInput(input: string): void {
  if (isAbsolute(input)) {
    throw new Error(`Absolute paths are not allowed: ${input}`);
  }
  const norm = normalizeRelPath(input);
  if (norm.split("/").includes("..")) {
    throw new Error(`Path traversal is not allowed: ${input}`);
  }
}

export function relativeProjectPath(absolutePath: string, cwd = process.cwd()): string {
  const rootReal = projectRootReal(cwd);
  return normalizeRelPath(relative(rootReal, absolutePath));
}

export function resolveContainedSqlPath(input: string, cwd = process.cwd()): string {
  assertRelativeInput(input);
  const norm = normalizeRelPath(input);
  if (!isUnderAllowlistedPrefix(norm)) {
    throw new Error(
      `Path must be under one of: ${SQL_PATH_ALLOWLIST_PREFIXES.join(", ")} (got ${input})`,
    );
  }

  const rootReal = projectRootReal(cwd);
  const candidate = resolve(rootReal, input);
  const targetReal = realpathSync.native(candidate);
  const rel = relative(rootReal, targetReal);
  if (!rel || rel.startsWith("..") || rel.split(sep).includes("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes project root: ${input}`);
  }

  const relNorm = normalizeRelPath(rel);
  if (!isUnderAllowlistedPrefix(relNorm)) {
    throw new Error(
      `Resolved path must stay under allowlisted dirs: ${SQL_PATH_ALLOWLIST_PREFIXES.join(", ")}`,
    );
  }

  return targetReal;
}

export function readContainedSqlFile(resolvedPath: string): { sql: string; contentHash: string } {
  const st = statSync(resolvedPath);
  if (!st.isFile()) {
    throw new Error(`Not a file: ${resolvedPath}`);
  }
  if (st.size > MAX_SQL_FILE_BYTES) {
    throw new Error(`SQL file exceeds ${MAX_SQL_FILE_BYTES} bytes: ${resolvedPath}`);
  }
  const sql = readFileSync(resolvedPath, "utf8");
  if (Buffer.byteLength(sql, "utf8") > MAX_SQL_FILE_BYTES) {
    throw new Error(`SQL file exceeds ${MAX_SQL_FILE_BYTES} bytes: ${resolvedPath}`);
  }
  const contentHash = createHash("sha256").update(sql, "utf8").digest("hex");
  return { sql, contentHash };
}

export function writeContainedSqlFile(
  relativePath: string,
  content: string,
  options: { expectedContentHash?: string; cwd?: string },
): string {
  const resolvedPath = resolveContainedSqlPath(relativePath, options.cwd ?? process.cwd());
  if (options.expectedContentHash) {
    const { contentHash } = readContainedSqlFile(resolvedPath);
    if (contentHash !== options.expectedContentHash) {
      throw new Error(
        `File changed since read; refusing write (hash mismatch for ${relativePath})`,
      );
    }
  }
  if (Buffer.byteLength(content, "utf8") > MAX_SQL_FILE_BYTES) {
    throw new Error(`Rewritten SQL exceeds ${MAX_SQL_FILE_BYTES} bytes`);
  }
  writeFileSync(resolvedPath, content, "utf8");
  return resolvedPath;
}

export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

export function assertLoopbackLlmBaseUrl(baseUrl: string): void {
  if (process.env.PG_LOCK_XRAY_ALLOW_REMOTE_LLM === "1") return;
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new Error(`Invalid LLM baseUrl: ${baseUrl}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`LLM baseUrl must be http(s): ${baseUrl}`);
  }
  if (!isLoopbackHost(u.hostname)) {
    throw new Error(
      `Non-loopback LLM baseUrl blocked (${u.hostname}). Set PG_LOCK_XRAY_ALLOW_REMOTE_LLM=1 to allow.`,
    );
  }
}
