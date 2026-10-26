use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const SQL_PATH_ALLOWLIST_PREFIXES: &[&str] = &[
    "migrations/",
    "prisma/",
    "supabase/",
    "sql/",
];

pub const MAX_SQL_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn normalize_rel_path(input: &str) -> String {
    input.replace('\\', "/")
}

fn is_under_allowlisted_prefix(rel_path: &str) -> bool {
    let norm = normalize_rel_path(rel_path);
    SQL_PATH_ALLOWLIST_PREFIXES.iter().any(|prefix| {
        let bare = prefix.trim_end_matches('/');
        norm == bare || norm.starts_with(prefix)
    })
}

pub fn project_root_real(cwd: &Path) -> PathBuf {
    let base = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    base
}

fn assert_relative_input(input: &str) -> Result<(), String> {
    let path = Path::new(input);
    if path.is_absolute() {
        return Err(format!("Absolute paths are not allowed: {input}"));
    }
    let norm = normalize_rel_path(input);
    if norm.split('/').any(|p| p == "..") {
        return Err(format!("Path traversal is not allowed: {input}"));
    }
    Ok(())
}

pub fn relative_project_path(absolute_path: &Path, cwd: &Path) -> String {
    let root_real = project_root_real(cwd);
    let rel = absolute_path
        .strip_prefix(&root_real)
        .unwrap_or(absolute_path);
    normalize_rel_path(rel.to_string_lossy().as_ref())
}

pub fn resolve_contained_sql_path(input: &str, cwd: &Path) -> Result<PathBuf, String> {
    assert_relative_input(input)?;
    let norm = normalize_rel_path(input);
    if !is_under_allowlisted_prefix(&norm) {
        return Err(format!(
            "Path must be under one of: {} (got {})",
            SQL_PATH_ALLOWLIST_PREFIXES.join(", "),
            input
        ));
    }

    let root_real = project_root_real(cwd);
    let candidate = root_real.join(input);
    let target_real = candidate
        .canonicalize()
        .map_err(|e| format!("Path escapes project root: {input} ({e})"))?;

    let rel = target_real
        .strip_prefix(&root_real)
        .map_err(|_| format!("Path escapes project root: {input}"))?;
    for component in rel.components() {
        if component == Component::ParentDir {
            return Err(format!("Path escapes project root: {input}"));
        }
    }

    let rel_norm = normalize_rel_path(rel.to_string_lossy().as_ref());
    if !is_under_allowlisted_prefix(&rel_norm) {
        return Err(format!(
            "Resolved path must stay under allowlisted dirs: {}",
            SQL_PATH_ALLOWLIST_PREFIXES.join(", ")
        ));
    }

    Ok(target_real)
}

pub struct SqlFileContents {
    pub sql: String,
    pub content_hash: String,
}

pub fn read_contained_sql_file(resolved_path: &Path) -> Result<SqlFileContents, String> {
    let meta = fs::metadata(resolved_path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("Not a file: {}", resolved_path.display()));
    }
    if meta.len() > MAX_SQL_FILE_BYTES {
        return Err(format!(
            "SQL file exceeds {} bytes: {}",
            MAX_SQL_FILE_BYTES,
            resolved_path.display()
        ));
    }
    let sql = fs::read_to_string(resolved_path).map_err(|e| e.to_string())?;
    if sql.len() as u64 > MAX_SQL_FILE_BYTES {
        return Err(format!(
            "SQL file exceeds {} bytes: {}",
            MAX_SQL_FILE_BYTES,
            resolved_path.display()
        ));
    }
    let content_hash = hex::encode(Sha256::digest(sql.as_bytes()));
    Ok(SqlFileContents { sql, content_hash })
}

pub fn write_contained_sql_file(
    relative_path: &str,
    content: &str,
    expected_content_hash: Option<&str>,
    cwd: &Path,
) -> Result<PathBuf, String> {
    let resolved_path = resolve_contained_sql_path(relative_path, cwd)?;
    if let Some(expected) = expected_content_hash {
        let current = read_contained_sql_file(&resolved_path)?;
        if current.content_hash != expected {
            return Err(format!(
                "File changed since read; refusing write (hash mismatch for {relative_path})"
            ));
        }
    }
    if content.len() as u64 > MAX_SQL_FILE_BYTES {
        return Err(format!("Rewritten SQL exceeds {} bytes", MAX_SQL_FILE_BYTES));
    }
    fs::write(&resolved_path, content).map_err(|e| e.to_string())?;
    Ok(resolved_path)
}

pub fn is_loopback_host(hostname: &str) -> bool {
    let host = hostname
        .trim_matches(|c| c == '[' || c == ']')
        .to_lowercase();
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, remove_dir_all, write};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pg-lock-xray-test-{stamp}"))
    }

    #[test]
    fn accepts_allowlisted_sql_paths() {
        let root = test_root();
        let sql_dir = root.join("sql");
        create_dir_all(&sql_dir).unwrap();
        write(sql_dir.join("ok.sql"), "SELECT 1;").unwrap();
        let resolved = resolve_contained_sql_path("sql/ok.sql", &root).unwrap();
        assert!(resolved.to_string_lossy().contains("ok.sql"));
        let _ = remove_dir_all(&root);
    }

    #[test]
    fn rejects_traversal_and_non_allowlisted() {
        let root = test_root();
        create_dir_all(&root).unwrap();
        write(root.join("package.json"), "{}").unwrap();
        assert!(resolve_contained_sql_path("sql/../package.json", &root)
            .unwrap_err()
            .to_lowercase()
            .contains("traversal"));
        assert!(resolve_contained_sql_path("package.json", &root)
            .unwrap_err()
            .contains("must be under"));
        let abs_input = if cfg!(windows) {
            r"C:\Windows\System32\drivers\etc\hosts"
        } else {
            "/etc/passwd"
        };
        assert!(resolve_contained_sql_path(abs_input, &root)
            .unwrap_err()
            .contains("Absolute"));
        let _ = remove_dir_all(&root);
    }
}
