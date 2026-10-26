export function rewriteStatement(sql: string): string {
  const trimmed = sql.trim().replace(/;\s*$/, "");
  if (!trimmed) return sql;

  if (/^CREATE\s+INDEX\b/i.test(trimmed) && !/\bCONCURRENTLY\b/i.test(trimmed)) {
    return trimmed.replace(/^CREATE\s+INDEX\b/i, "CREATE INDEX CONCURRENTLY") + ";";
  }

  const fkMatch = trimmed.match(
    /^ALTER\s+TABLE\s+(\S+)\s+ADD\s+CONSTRAINT\s+(\S+)\s+FOREIGN\s+KEY\s*\(([^)]+)\)\s+REFERENCES\s+(\S+)\s*\(([^)]+)\)\s*;?$/i,
  );
  if (fkMatch && !/\bNOT\s+VALID\b/i.test(trimmed)) {
    const [, table, name, cols, refTable, refCols] = fkMatch;
    const add = `ALTER TABLE ${table} ADD CONSTRAINT ${name} FOREIGN KEY (${cols}) REFERENCES ${refTable} (${refCols}) NOT VALID;`;
    const validate = `ALTER TABLE ${table} VALIDATE CONSTRAINT ${name};`;
    return `${add}\n${validate}`;
  }

  return trimmed.endsWith(";") ? trimmed : `${trimmed};`;
}

export function rewriteSqlDocument(sql: string): string {
  const parts = splitSqlStatements(sql);
  return parts.map((p) => rewriteStatement(p)).join("\n");
}

export function unifiedDiff(before: string, after: string, label = "migration.sql"): string {
  const bLines = before.split("\n");
  const aLines = after.split("\n");
  const out = [`--- a/${label}`, `+++ b/${label}`];
  const max = Math.max(bLines.length, aLines.length);
  for (let i = 0; i < max; i++) {
    const oldL = bLines[i];
    const newL = aLines[i];
    if (oldL === newL) {
      if (oldL !== undefined) out.push(` ${oldL}`);
    } else {
      if (oldL !== undefined) out.push(`-${oldL}`);
      if (newL !== undefined) out.push(`+${newL}`);
    }
  }
  return out.join("\n");
}

function splitSqlStatements(sql: string): string[] {
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
