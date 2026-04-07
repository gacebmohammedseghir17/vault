use std::time::Duration;

use sysinfo::System;

fn is_shadow_ai_process(name: &str, cmdline: &str) -> bool {
    let n = name.to_lowercase();
    let c = cmdline.to_lowercase();

    if n.contains("ollama")
        || n.contains("llama")
        || n.contains("llama-server")
        || n.contains("kobold")
        || n.contains("lmstudio")
        || n.contains("open-webui")
        || n.contains("text-generation-webui")
    {
        return true;
    }

    if (n == "python.exe" || n == "python" || n == "py.exe")
        && (c.contains("transformers")
            || c.contains("torch")
            || c.contains("llama_cpp")
            || c.contains("vllm")
            || c.contains("text-generation-webui"))
    {
        return true;
    }

    false
}

pub fn scan_once() {
    let mut sys = System::new_all();
    sys.refresh_all();

    for (_pid, proc_) in sys.processes() {
        let name = proc_.name();
        let cmd = proc_.cmd().join(" ");
        if is_shadow_ai_process(name, &cmd) {
            println!(
                "\x1b[33m[SHADOW-AI] Potential unauthorized local inference engine: {} | {}\x1b[0m",
                name,
                cmd
            );
        }
    }
}

pub fn start_background_monitor() {
    std::thread::spawn(|| loop {
        scan_once();
        std::thread::sleep(Duration::from_secs(30));
    });
}

