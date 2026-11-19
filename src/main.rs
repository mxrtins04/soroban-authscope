use soroban_authscope::{AuthScope, MarkdownReporter, TraceParser, TreeVisualizer};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        println!("soroban-authscope: Hierarchical authorization tree analyzer for Soroban contracts");
        println!();
        println!("Usage:");
        println!("  soroban-authscope <trace.json> [--format <text|markdown|json>]");
        println!("  soroban-authscope --help");
        process::exit(0);
    }

    let file_path = &args[1];
    let mut format = "text";
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--format" && i + 1 < args.len() {
            format = &args[i + 1];
            i += 2;
        } else {
            i += 1;
        }
    }

    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading trace file '{}': {}", file_path, e);
            process::exit(1);
        }
    };

    let root = match TraceParser::parse_json(&content) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("Error parsing JSON invocation trace: {}", e);
            process::exit(1);
        }
    };

    let scope = AuthScope::strict_non_wildcard();
    let res = scope.analyze(&root);

    match format {
        "markdown" => {
            let report = match &res {
                Ok(r) => r,
                Err(r) => r,
            };
            println!("{}", MarkdownReporter::format(report));
        }
        "json" => {
            let report = match &res {
                Ok(r) => r,
                Err(r) => r,
            };
            println!("{}", serde_json::to_string_pretty(report).unwrap());
        }
        _ => {
            println!("{}", TreeVisualizer::format_ascii(&root));
            match &res {
                Ok(report) => {
                    println!("Status: PASS (All {} invocation nodes strictly authorized)", report.total_nodes_scanned);
                }
                Err(report) => {
                    eprintln!("Status: FAIL (Detected {} authorization violation(s)):", report.violations.len());
                    for (i, v) in report.violations.iter().enumerate() {
                        eprintln!("  {}. {}", i + 1, v);
                    }
                }
            }
        }
    }

    if res.is_err() {
        process::exit(2);
    }
}
