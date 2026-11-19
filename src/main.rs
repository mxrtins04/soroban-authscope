use soroban_authscope::{AuthScope, InvocationNode, TreeVisualizer};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        println!("soroban-authscope: Hierarchical authorization tree analyzer for Soroban contracts");
        println!();
        println!("Usage:");
        println!("  soroban-authscope <trace.json> [--strict]");
        println!("  soroban-authscope --help");
        process::exit(0);
    }

    let file_path = &args[1];
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading trace file '{}': {}", file_path, e);
            process::exit(1);
        }
    };

    let root: InvocationNode = match serde_json::from_str(&content) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("Error parsing JSON invocation trace: {}", e);
            process::exit(1);
        }
    };

    println!("{}", TreeVisualizer::format_ascii(&root));

    let scope = AuthScope::strict_non_wildcard();
    match scope.analyze(&root) {
        Ok(report) => {
            println!("Status: PASS (All {} invocation nodes strictly authorized)", report.total_nodes_scanned);
        }
        Err(report) => {
            eprintln!("Status: FAIL (Detected {} authorization violation(s)):", report.violations.len());
            for (i, v) in report.violations.iter().enumerate() {
                eprintln!("  {}. {}", i + 1, v);
            }
            process::exit(2);
        }
    }
}
