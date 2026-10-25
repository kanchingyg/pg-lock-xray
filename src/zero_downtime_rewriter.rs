use regex::Regex;

pub fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for c in sql.chars() {
        if c == '\'' && !in_double {
            in_single = !in_single;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
        }
        if c == ';' && !in_single && !in_double {
            let piece = cur.trim();
            if !piece.is_empty() {
                out.push(piece.to_string());
            }
            cur.clear();
            continue;
        }
        cur.push(c);
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

pub fn rewrite_statement(sql: &str) -> String {
    let trimmed = sql.trim().trim_end_matches(';');
    if trimmed.is_empty() {
        return sql.to_string();
    }

    if Regex::new(r"(?i)^CREATE\s+INDEX\b")
        .unwrap()
        .is_match(trimmed)
        && !Regex::new(r"(?i)\bCONCURRENTLY\b")
            .unwrap()
            .is_match(trimmed)
    {
        let rewritten = Regex::new(r"(?i)^CREATE\s+INDEX\b")
            .unwrap()
            .replace(trimmed, "CREATE INDEX CONCURRENTLY");
        return format!("{};", rewritten);
    }

    let fk_re = Regex::new(
        r"(?i)^ALTER\s+TABLE\s+(\S+)\s+ADD\s+CONSTRAINT\s+(\S+)\s+FOREIGN\s+KEY\s*\(([^)]+)\)\s+REFERENCES\s+(\S+)\s*\(([^)]+)\)\s*;?$",
    )
    .unwrap();
    if let Some(m) = fk_re.captures(trimmed) {
        if !Regex::new(r"(?i)\bNOT\s+VALID\b").unwrap().is_match(trimmed) {
            let table = m.get(1).unwrap().as_str();
            let name = m.get(2).unwrap().as_str();
            let cols = m.get(3).unwrap().as_str();
            let ref_table = m.get(4).unwrap().as_str();
            let ref_cols = m.get(5).unwrap().as_str();
            let add = format!(
                "ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY ({cols}) REFERENCES {ref_table} ({ref_cols}) NOT VALID;"
            );
            let validate = format!("ALTER TABLE {table} VALIDATE CONSTRAINT {name};");
            return format!("{add}\n{validate}");
        }
    }

    if trimmed.ends_with(';') {
        trimmed.to_string()
    } else {
        format!("{trimmed};")
    }
}

pub fn rewrite_sql_document(sql: &str) -> String {
    split_sql_statements(sql)
        .iter()
        .map(|p| rewrite_statement(p))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn unified_diff(before: &str, after: &str, label: &str) -> String {
    let b_lines: Vec<&str> = before.split('\n').collect();
    let a_lines: Vec<&str> = after.split('\n').collect();
    let mut out = vec![
        format!("--- a/{label}"),
        format!("+++ b/{label}"),
    ];
    let max = b_lines.len().max(a_lines.len());
    for i in 0..max {
        let old_l = b_lines.get(i);
        let new_l = a_lines.get(i);
        match (old_l, new_l) {
            (Some(o), Some(n)) if o == n => out.push(format!(" {o}")),
            _ => {
                if let Some(o) = old_l {
                    out.push(format!("-{o}"));
                }
                if let Some(n) = new_l {
                    out.push(format!("+{n}"));
                }
            }
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"
CREATE INDEX idx_users_email ON users(email);
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);
";

    #[test]
    fn rewrites_concurrently_and_not_valid() {
        let out = rewrite_sql_document(SAMPLE);
        assert!(out.to_uppercase().contains("CREATE INDEX CONCURRENTLY"));
        assert!(out.to_uppercase().contains("NOT VALID"));
        assert!(out.contains("VALIDATE CONSTRAINT fk_user"));
    }
}
