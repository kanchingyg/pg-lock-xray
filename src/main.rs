use std::env;
use std::io::{self, Write};
use std::path::Path;

use pg_lock_xray::mcp::{run_mcp_server, set_guards};
use pg_lock_xray::sql_analyzer::{analyze_target, build_fix_preview, resolve_sql_input};
use pg_lock_xray::sql_path::write_contained_sql_file;
use pg_lock_xray::VERSION;

struct ParsedArgs {
    flags: Vec<String>,
    rest: Vec<String>,
}

fn parse_argv(argv: &[String]) -> ParsedArgs {
    let flags: Vec<String> = argv.iter().filter(|a| a.starts_with("--")).cloned().collect();
    let rest: Vec<String> = argv.iter().filter(|a| !a.starts_with("--")).cloned().collect();
    ParsedArgs { flags, rest }
}

fn has_flag(flags: &[String], name: &str) -> bool {
    flags.iter().any(|f| f == name)
}

fn run_cli(root: &Path, parsed: &ParsedArgs) -> i32 {
    let dry_run = has_flag(&parsed.flags, "--dry-run");
    let allow_write = has_flag(&parsed.flags, "--allow-write");
    set_guards(allow_write, dry_run);

    if has_flag(&parsed.flags, "--mcp") {
        if let Err(e) = run_mcp_server(root, VERSION) {
            eprintln!("{e}");
            return 1;
        }
        return 0;
    }

    let fix_mode = has_flag(&parsed.flags, "--fix");
    let target = parsed.rest.first();

    if target.is_none() {
        let _ = writeln!(
            io::stderr(),
            "Usage: pg-lock-xray <dir-or.sql> | pg-lock-xray --fix <file.sql> [--dry-run] [--allow-write] | pg-lock-xray --mcp"
        );
        return 2;
    }
    let target = target.unwrap();

    let result: Result<i32, String> = (|| {
        if fix_mode {
            let resolved = resolve_sql_input(target, root)?;
            let preview = build_fix_preview(&resolved.sql, Some(&resolved.source));
            if dry_run || !allow_write {
                print!("{}\n", preview.diff);
                return Ok(0);
            }
            if resolved.source == "inline" {
                return Err("Cannot write inline SQL; pass a file path.".into());
            }
            write_contained_sql_file(
                &resolved.source,
                &preview.rewritten,
                resolved.content_hash.as_deref(),
                root,
            )?;
            println!("Rewrote {}", resolved.source);
            return Ok(0);
        }

        let reports = analyze_target(target, root)?;
        for r in &reports {
            println!("\n# {} ({} critical)", r.source, r.critical_count);
            for s in &r.statements {
                if s.statement == "(file)" && s.risks.is_empty() {
                    continue;
                }
                let stmt_preview = if s.statement.len() > 120 {
                    s.statement.chars().take(120).collect::<String>()
                } else {
                    s.statement.clone()
                };
                println!(
                    "[{}] {} — {}\n  {}",
                    match s.severity {
                        pg_lock_xray::lock_rules::Severity::CRITICAL => "CRITICAL",
                        pg_lock_xray::lock_rules::Severity::WARNING => "WARNING",
                        pg_lock_xray::lock_rules::Severity::INFO => "INFO",
                    },
                    s.lock_mode.as_str(),
                    s.message,
                    stmt_preview
                );
            }
        }
        let total_critical = reports.iter().map(|r| r.critical_count).sum::<usize>();
        Ok(if total_critical > 0 { 1 } else { 0 })
    })();

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    let parsed = parse_argv(&argv);
    let root = env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());

    let dry_run = has_flag(&parsed.flags, "--dry-run");
    let allow_write = has_flag(&parsed.flags, "--allow-write");
    set_guards(allow_write, dry_run);

    if has_flag(&parsed.flags, "--mcp") {
        if let Err(e) = run_mcp_server(&root, VERSION) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }

    let code = run_cli(&root, &parsed);
    std::process::exit(code);
}
