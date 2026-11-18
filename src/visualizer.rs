use crate::types::InvocationNode;
use serde_json;

pub struct TreeVisualizer;

impl TreeVisualizer {
    pub fn format_ascii(root: &InvocationNode) -> String {
        let mut buffer = String::new();
        buffer.push_str("┌─ AuthorizedInvocation DAG\n");
        Self::render_node(root, "", true, &mut buffer);
        buffer
    }

    fn render_node(node: &InvocationNode, prefix: &str, is_last: bool, buffer: &mut String) {
        let branch = if is_last { "└── " } else { "├── " };
        let auth_badge = if node.is_authorized {
            "[AUTH: ✓]"
        } else {
            "[AUTH: ✗ MISSING]"
        };

        buffer.push_str(&format!(
            "{}{}{} {}::{}({})\n",
            prefix,
            branch,
            auth_badge,
            node.function.contract,
            node.function.function_name,
            node.function
                .args
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));

        let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        let total_subs = node.sub_invocations.len();
        for (i, sub) in node.sub_invocations.iter().enumerate() {
            Self::render_node(sub, &next_prefix, i == total_subs - 1, buffer);
        }
    }

    pub fn to_json_trace(root: &InvocationNode) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(root)
    }
}
