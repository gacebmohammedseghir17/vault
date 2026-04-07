use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Node {
    Process { pid: u32, name: String },
    File { path: String },
    Socket { ip: String, port: u16 },
}

pub struct TopologyEngine {
    graph: DiGraph<Node, String>,
    node_map: HashMap<String, NodeIndex>,
    max_nodes: usize,
}

impl TopologyEngine {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            max_nodes: 10_000,
        }
    }

    pub fn track_process_spawn(
        &mut self,
        parent_pid: u32,
        parent_name: String,
        child_pid: u32,
        child_name: String,
    ) -> Option<String> {
        if self.node_map.len() > self.max_nodes {
            self.graph = DiGraph::new();
            self.node_map.clear();
        }

        let p_key = format!("PROC:{}", parent_pid);
        let c_key = format!("PROC:{}", child_pid);

        let p_idx = *self.node_map.entry(p_key).or_insert_with(|| {
            self.graph
                .add_node(Node::Process { pid: parent_pid, name: parent_name })
        });
        let c_idx = *self.node_map.entry(c_key).or_insert_with(|| {
            self.graph
                .add_node(Node::Process { pid: child_pid, name: child_name })
        });

        self.graph.add_edge(p_idx, c_idx, "SPAWNED".to_string());
        self.analyze_spawn(p_idx, c_idx)
    }

    fn analyze_spawn(&self, parent: NodeIndex, child: NodeIndex) -> Option<String> {
        let p_node = &self.graph[parent];
        let c_node = &self.graph[child];

        if let (Node::Process { name: p_name, .. }, Node::Process { name: c_name, .. }) = (p_node, c_node) {
            let p = p_name.to_lowercase();
            let c = c_name.to_lowercase();

            let office_parent = p.contains("winword") || p.contains("excel") || p.contains("powerpnt") || p.contains("outlook");
            let shell_child = c.contains("cmd.exe") || c.contains("powershell") || c.contains("pwsh.exe") || c.contains("wscript.exe") || c.contains("cscript.exe");

            if office_parent && shell_child {
                return Some("MALICIOUS_TOPOLOGY: Office spawning shell".to_string());
            }

            if p.contains("svchost") && (c.contains("powershell") || c.contains("cmd.exe")) {
                return Some("MALICIOUS_TOPOLOGY: svchost spawning shell".to_string());
            }

            if p.contains("explorer") && (c.contains("rundll32") || c.contains("regsvr32")) {
                return Some("SUSPICIOUS_TOPOLOGY: explorer spawning LOLBin".to_string());
            }
        }

        None
    }
}

