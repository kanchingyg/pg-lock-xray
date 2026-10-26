use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgLockMode {
    AccessExclusive,
    ShareUpdateExclusive,
    Share,
    ShareRowExclusive,
    AccessShare,
    RowExclusive,
    RowShare,
    None,
}

impl Serialize for PgLockMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PgLockMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "ACCESS EXCLUSIVE" => Self::AccessExclusive,
            "SHARE UPDATE EXCLUSIVE" => Self::ShareUpdateExclusive,
            "SHARE" => Self::Share,
            "SHARE ROW EXCLUSIVE" => Self::ShareRowExclusive,
            "ACCESS SHARE" => Self::AccessShare,
            "ROW EXCLUSIVE" => Self::RowExclusive,
            "ROW SHARE" => Self::RowShare,
            "NONE" => Self::None,
            _ => Self::None,
        })
    }
}

impl PgLockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessExclusive => "ACCESS EXCLUSIVE",
            Self::ShareUpdateExclusive => "SHARE UPDATE EXCLUSIVE",
            Self::Share => "SHARE",
            Self::ShareRowExclusive => "SHARE ROW EXCLUSIVE",
            Self::AccessShare => "ACCESS SHARE",
            Self::RowExclusive => "ROW EXCLUSIVE",
            Self::RowShare => "ROW SHARE",
            Self::None => "NONE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    CRITICAL,
    WARNING,
    INFO,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskCode {
    IndexWithoutConcurrently,
    VectorIndexWithoutConcurrently,
    FkWithoutNotValid,
    VolatileDefault,
    MissingLockTimeout,
    VectorDimensionMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementFinding {
    pub statement: String,
    pub lock_mode: PgLockMode,
    pub severity: Severity,
    pub risks: Vec<RiskCode>,
    pub message: String,
}

static VOLATILE_DEFAULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bDEFAULT\s+(?:now|current_timestamp|random|gen_random_uuid|uuid_generate|nextval)\s*\(",
    )
    .unwrap()
});
static VECTOR_INDEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bUSING\s+(?:hnsw|ivfflat)\b").unwrap());
static VECTOR_DIM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)vector\s*\(\s*(\d+)\s*\)").unwrap());

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn classify_statement(sql: &str) -> StatementFinding {
    let normalized = normalize_sql(sql);
    let mut risks: Vec<RiskCode> = Vec::new();
    let mut lock_mode = PgLockMode::None;
    let mut severity = Severity::INFO;
    let mut message = "No blocking DDL detected.".to_string();

    if Regex::new(r"(?i)^CREATE\s+INDEX\b")
        .unwrap()
        .is_match(&normalized)
    {
        let concurrent = Regex::new(r"(?i)\bCONCURRENTLY\b")
            .unwrap()
            .is_match(&normalized);
        if VECTOR_INDEX_RE.is_match(&normalized) && !concurrent {
            risks.push(RiskCode::VectorIndexWithoutConcurrently);
            lock_mode = PgLockMode::AccessExclusive;
            severity = Severity::CRITICAL;
            message =
                "pgvector index build blocks writes; use CREATE INDEX CONCURRENTLY.".to_string();
        } else if !concurrent {
            risks.push(RiskCode::IndexWithoutConcurrently);
            lock_mode = PgLockMode::AccessExclusive;
            severity = Severity::CRITICAL;
            message =
                "CREATE INDEX takes ACCESS EXCLUSIVE; use CONCURRENTLY for zero downtime."
                    .to_string();
        } else {
            lock_mode = PgLockMode::ShareUpdateExclusive;
            severity = Severity::INFO;
            message =
                "CREATE INDEX CONCURRENTLY uses SHARE UPDATE EXCLUSIVE (safer).".to_string();
        }
    } else if Regex::new(r"(?i)^ALTER\s+TABLE\b")
        .unwrap()
        .is_match(&normalized)
        && Regex::new(r"(?i)\bADD\s+CONSTRAINT\b")
            .unwrap()
            .is_match(&normalized)
    {
        if Regex::new(r"(?i)\bFOREIGN\s+KEY\b")
            .unwrap()
            .is_match(&normalized)
            && !Regex::new(r"(?i)\bNOT\s+VALID\b")
                .unwrap()
                .is_match(&normalized)
        {
            risks.push(RiskCode::FkWithoutNotValid);
            lock_mode = PgLockMode::AccessExclusive;
            severity = Severity::CRITICAL;
            message =
                "FK validation scans parent table; add NOT VALID then VALIDATE CONSTRAINT."
                    .to_string();
        } else if Regex::new(r"(?i)\bFOREIGN\s+KEY\b").unwrap().is_match(&normalized) {
            lock_mode = PgLockMode::ShareRowExclusive;
            severity = Severity::WARNING;
            message =
                "NOT VALID FK added; run VALIDATE CONSTRAINT before relying on it.".to_string();
        } else {
            lock_mode = PgLockMode::AccessExclusive;
            severity = Severity::WARNING;
            message = "ALTER TABLE ADD CONSTRAINT may block writers.".to_string();
        }
    } else if Regex::new(r"(?i)^ALTER\s+TABLE\b")
        .unwrap()
        .is_match(&normalized)
        && Regex::new(r"(?i)\bADD\s+COLUMN\b")
            .unwrap()
            .is_match(&normalized)
    {
        lock_mode = PgLockMode::AccessExclusive;
        if VOLATILE_DEFAULT_RE.is_match(&normalized) {
            risks.push(RiskCode::VolatileDefault);
            severity = Severity::CRITICAL;
            message =
                "Volatile DEFAULT on ADD COLUMN rewrites table; use multi-step expand.".to_string();
        } else {
            severity = Severity::WARNING;
            message =
                "ADD COLUMN may take ACCESS EXCLUSIVE on older Postgres versions.".to_string();
        }
    } else if Regex::new(r"(?i)^DROP\s+TABLE\b").unwrap().is_match(&normalized)
        || Regex::new(r"(?i)^TRUNCATE\b").unwrap().is_match(&normalized)
    {
        lock_mode = PgLockMode::AccessExclusive;
        severity = Severity::CRITICAL;
        message = "Destructive DDL holds ACCESS EXCLUSIVE.".to_string();
    } else if Regex::new(r"(?i)^CREATE\s+TABLE\b").unwrap().is_match(&normalized) {
        lock_mode = PgLockMode::AccessExclusive;
        severity = Severity::WARNING;
        message =
            "CREATE TABLE is usually fine in empty DB; blocks concurrent DDL on name clash."
                .to_string();
    }

    let dims: Vec<i32> = VECTOR_DIM_RE
        .captures_iter(&normalized)
        .filter_map(|c| c.get(1).and_then(|m| m.as_str().parse().ok()))
        .collect();
    if dims.len() >= 2 {
        let unique: std::collections::HashSet<i32> = dims.iter().copied().collect();
        if unique.len() > 1 {
            risks.push(RiskCode::VectorDimensionMismatch);
            if severity == Severity::INFO {
                severity = Severity::WARNING;
            }
            message = format!(
                "Mixed vector dimensions ({}); index/query mismatch risk.",
                dims.iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    StatementFinding {
        statement: normalized,
        lock_mode,
        severity,
        risks,
        message,
    }
}

pub fn file_level_findings(sql_text: &str) -> Vec<StatementFinding> {
    let mut findings = Vec::new();
    if !Regex::new(r"(?i)\bSET\s+lock_timeout\b")
        .unwrap()
        .is_match(sql_text)
    {
        findings.push(StatementFinding {
            statement: "(file)".into(),
            lock_mode: PgLockMode::None,
            severity: Severity::WARNING,
            risks: vec![RiskCode::MissingLockTimeout],
            message: "No SET lock_timeout; long locks may stall app traffic.".into(),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_index_without_concurrently() {
        let f = classify_statement("CREATE INDEX idx ON users(email);");
        assert_eq!(f.severity, Severity::CRITICAL);
        assert!(f.risks.contains(&RiskCode::IndexWithoutConcurrently));
    }

    #[test]
    fn flags_fk_without_not_valid() {
        let f = classify_statement(
            "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);",
        );
        assert_eq!(f.severity, Severity::CRITICAL);
        assert!(f.risks.contains(&RiskCode::FkWithoutNotValid));
    }
}
