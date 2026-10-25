use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::lock_rules::{classify_statement, file_level_findings, StatementFinding};
use crate::sql_path::{
    read_contained_sql_file, relative_project_path, resolve_contained_sql_path,
};
use crate::zero_downtime_rewriter::{rewrite_sql_document, split_sql_statements, unified_diff};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub source: String,
    pub statements: Vec<StatementFinding>,
    pub critical_count: usize,
}

pub fn analyze_sql_text(sql: &str, source: &str) -> AnalysisReport {
    let stmts = split_sql_statements(sql);
    let statements: Vec<StatementFinding> = file_level_findings(sql)
        .into_iter()
        .chain(stmts.iter().map(|s| classify_statement(s)))
        .collect();
    let critical_count = statements
        .iter()
        .filter(|s| s.severity == crate::lock_rules::Severity::CRITICAL)
        .count();
    AnalysisReport {
        source: source.to_string(),
        statements,
        critical_count,
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedSqlInput {
    pub sql: String,
    pub source: String,
    pub content_hash: Option<String>,
}

pub fn resolve_sql_input(sql_or_path: &str, cwd: &Path) -> Result<ResolvedSqlInput, String> {
    let looks_like_sql = sql_or_path.contains('\n')
        || Regex::new(r"(?i)^\s*(CREATE|ALTER|DROP|SET|INSERT|UPDATE|DELETE)\b")
            .unwrap()
            .is_match(sql_or_path);
    if looks_like_sql {
        return Ok(ResolvedSqlInput {
            sql: sql_or_path.to_string(),
            source: "inline".into(),
            content_hash: None,
        });
    }
    let resolved_path = resolve_contained_sql_path(sql_or_path, cwd)?;
    let contents = read_contained_sql_file(&resolved_path)?;
    Ok(ResolvedSqlInput {
        sql: contents.sql,
        source: sql_or_path.to_string(),
        content_hash: Some(contents.content_hash),
    })
}

fn collect_sql_files(target_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_sql_files_inner(target_dir, &mut files)?;
    Ok(files)
}

fn collect_sql_files_inner(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            collect_sql_files_inner(&path, files)?;
        } else if meta.is_file() {
            if path.extension().and_then(|e| e.to_str()).unwrap_or("").eq_ignore_ascii_case("sql") {
                files.push(path);
            }
        }
    }
    Ok(())
}

pub fn analyze_target(target: &str, cwd: &Path) -> Result<Vec<AnalysisReport>, String> {
    let resolved_target = resolve_contained_sql_path(target, cwd)?;
    let meta = fs::metadata(&resolved_target).map_err(|e| e.to_string())?;
    if meta.is_file() {
        let input = resolve_sql_input(target, cwd)?;
        return Ok(vec![analyze_sql_text(&input.sql, &input.source)]);
    }
    let files = collect_sql_files(&resolved_target)?;
    let reports = files
        .iter()
        .map(|f| {
            let contents = read_contained_sql_file(f)?;
            let source = relative_project_path(f, cwd);
            Ok(analyze_sql_text(&contents.sql, &source))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(reports)
}

pub struct FixPreview {
    pub rewritten: String,
    pub diff: String,
}

pub fn build_fix_preview(sql: &str, label: Option<&str>) -> FixPreview {
    let rewritten = rewrite_sql_document(sql);
    let diff = unified_diff(
        sql.trim_end(),
        rewritten.trim_end(),
        label.unwrap_or("migration.sql"),
    );
    FixPreview { rewritten, diff }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, remove_dir_all, write};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SAMPLE_SQL: &str = r"
CREATE INDEX idx_users_email ON users(email);
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);
";

    fn test_root() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pg-lock-xray-analyze-{stamp}"))
    }

    #[test]
    fn flags_critical_risks() {
        let report = analyze_sql_text(SAMPLE_SQL, "inline");
        let critical = report
            .statements
            .iter()
            .filter(|s| s.severity == crate::lock_rules::Severity::CRITICAL)
            .count();
        assert!(critical >= 2);
    }

    #[test]
    fn scans_allowlisted_directory() {
        let root = test_root();
        let sql_dir = root.join("sql");
        create_dir_all(&sql_dir).unwrap();
        write(sql_dir.join("ok.sql"), SAMPLE_SQL).unwrap();
        write(root.join("package.json"), "{}").unwrap();
        let reports = analyze_target("sql", &root).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].critical_count >= 2);
        let _ = remove_dir_all(&root);
    }
}
