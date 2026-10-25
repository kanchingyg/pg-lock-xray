export type PgLockMode =
  | "ACCESS EXCLUSIVE"
  | "SHARE UPDATE EXCLUSIVE"
  | "SHARE"
  | "SHARE ROW EXCLUSIVE"
  | "ACCESS SHARE"
  | "ROW EXCLUSIVE"
  | "ROW SHARE"
  | "NONE";

export type Severity = "CRITICAL" | "WARNING" | "INFO";

export type RiskCode =
  | "index-without-concurrently"
  | "vector-index-without-concurrently"
  | "fk-without-not-valid"
  | "volatile-default"
  | "missing-lock-timeout"
  | "vector-dimension-mismatch";

export type StatementFinding = {
  statement: string;
  lockMode: PgLockMode;
  severity: Severity;
  risks: RiskCode[];
  message: string;
};

const VOLATILE_DEFAULT_RE =
  /\bDEFAULT\s+(?:now|current_timestamp|random|gen_random_uuid|uuid_generate|nextval)\s*\(/i;

const VECTOR_INDEX_RE = /\bUSING\s+(?:hnsw|ivfflat)\b/i;
const VECTOR_DIM_RE = /vector\s*\(\s*(\d+)\s*\)/gi;

export function classifyStatement(sql: string): StatementFinding {
  const normalized = sql.replace(/\s+/g, " ").trim();
  const upper = normalized.toUpperCase();
  const risks: RiskCode[] = [];
  let lockMode: PgLockMode = "NONE";
  let severity: Severity = "INFO";
  let message = "No blocking DDL detected.";

  if (/^CREATE\s+INDEX\b/i.test(normalized)) {
    const concurrent = /\bCONCURRENTLY\b/i.test(normalized);
    if (VECTOR_INDEX_RE.test(normalized) && !concurrent) {
      risks.push("vector-index-without-concurrently");
      lockMode = "ACCESS EXCLUSIVE";
      severity = "CRITICAL";
      message = "pgvector index build blocks writes; use CREATE INDEX CONCURRENTLY.";
    } else if (!concurrent) {
      risks.push("index-without-concurrently");
      lockMode = "ACCESS EXCLUSIVE";
      severity = "CRITICAL";
      message = "CREATE INDEX takes ACCESS EXCLUSIVE; use CONCURRENTLY for zero downtime.";
    } else {
      lockMode = "SHARE UPDATE EXCLUSIVE";
      severity = "INFO";
      message = "CREATE INDEX CONCURRENTLY uses SHARE UPDATE EXCLUSIVE (safer).";
    }
  } else if (/^ALTER\s+TABLE\b/i.test(normalized) && /\bADD\s+CONSTRAINT\b/i.test(normalized)) {
    if (/\bFOREIGN\s+KEY\b/i.test(normalized) && !/\bNOT\s+VALID\b/i.test(normalized)) {
      risks.push("fk-without-not-valid");
      lockMode = "ACCESS EXCLUSIVE";
      severity = "CRITICAL";
      message = "FK validation scans parent table; add NOT VALID then VALIDATE CONSTRAINT.";
    } else if (/\bFOREIGN\s+KEY\b/i.test(normalized)) {
      lockMode = "SHARE ROW EXCLUSIVE";
      severity = "WARNING";
      message = "NOT VALID FK added; run VALIDATE CONSTRAINT before relying on it.";
    } else {
      lockMode = "ACCESS EXCLUSIVE";
      severity = "WARNING";
      message = "ALTER TABLE ADD CONSTRAINT may block writers.";
    }
  } else if (/^ALTER\s+TABLE\b/i.test(normalized) && /\bADD\s+COLUMN\b/i.test(normalized)) {
    lockMode = "ACCESS EXCLUSIVE";
    if (VOLATILE_DEFAULT_RE.test(normalized)) {
      risks.push("volatile-default");
      severity = "CRITICAL";
      message = "Volatile DEFAULT on ADD COLUMN rewrites table; use multi-step expand.";
    } else {
      severity = "WARNING";
      message = "ADD COLUMN may take ACCESS EXCLUSIVE on older Postgres versions.";
    }
  } else if (/^DROP\s+TABLE\b/i.test(normalized) || /^TRUNCATE\b/i.test(normalized)) {
    lockMode = "ACCESS EXCLUSIVE";
    severity = "CRITICAL";
    message = "Destructive DDL holds ACCESS EXCLUSIVE.";
  } else if (/^CREATE\s+TABLE\b/i.test(normalized)) {
    lockMode = "ACCESS EXCLUSIVE";
    severity = "WARNING";
    message = "CREATE TABLE is usually fine in empty DB; blocks concurrent DDL on name clash.";
  }

  const dims = [...normalized.matchAll(VECTOR_DIM_RE)].map((m) => parseInt(m[1], 10));
  if (dims.length >= 2 && new Set(dims).size > 1) {
    risks.push("vector-dimension-mismatch");
    if (severity === "INFO") severity = "WARNING";
    message = `Mixed vector dimensions (${dims.join(", ")}); index/query mismatch risk.`;
  }

  return { statement: normalized, lockMode, severity, risks, message };
}

export function fileLevelFindings(sqlText: string): StatementFinding[] {
  const findings: StatementFinding[] = [];
  if (!/\bSET\s+lock_timeout\b/i.test(sqlText)) {
    findings.push({
      statement: "(file)",
      lockMode: "NONE",
      severity: "WARNING",
      risks: ["missing-lock-timeout"],
      message: "No SET lock_timeout; long locks may stall app traffic.",
    });
  }
  return findings;
}
