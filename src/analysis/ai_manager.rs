use std::process::Command;
use std::thread;
use std::time::Duration;
use reqwest::Client;
use serde_json::json;
// use console::style;

pub struct AiManager {
    base_url: String,
    model: String,
    client: Client,
}

impl AiManager {
    pub fn new(model: &str) -> Self {
        Self {
            base_url: "http://localhost:11434".to_string(),
            model: model.to_string(),
            client: Client::new(),
        }
    }

    /// The "Advanced" Check: Ensures everything is ready before we scan
    pub async fn ensure_active(&self) -> bool {
        // 1. Is Ollama Running?
        if !self.is_service_up().await {
            println!("    [!] AI Service is DOWN. Attempting to start...");
            if self.start_service() {
                // Wait for it to boot
                println!("    [*] Waiting for AI Service to boot...");
                thread::sleep(Duration::from_secs(5));
            } else {
                return false;
            }
        }

        // 2. Is the Model Installed?
        if !self.has_model().await {
            println!("    [!] Model '{}' missing. Pulling from registry...", self.model);
            // In a real scenario, trigger 'ollama pull'. For now, warn the user.
            println!("    [!] Please run: ollama pull {}", self.model);
            return false;
        }

        true
    }

    async fn is_service_up(&self) -> bool {
        self.client.get(&self.base_url).send().await.is_ok()
    }

    fn start_service(&self) -> bool {
        // Try to start Ollama in the background
        // Windows-specific command
        let child = Command::new("cmd")
            .args(&["/C", "start", "/B", "ollama", "serve"])
            .spawn();
            
        match child {
            Ok(_) => true,
            Err(e) => {
                println!("    [!] Failed to auto-start Ollama: {}", e);
                false
            }
        }
    }

    async fn has_model(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        if let Ok(res) = self.client.get(&url).send().await {
            if let Ok(json) = res.json::<serde_json::Value>().await {
                if let Some(models) = json["models"].as_array() {
                    for m in models {
                        if let Some(name) = m["name"].as_str() {
                            if name.contains(&self.model) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    pub async fn ask(&self, prompt: String) -> String {
        let url = format!("{}/api/generate", self.base_url);
        // Remove stream:false entirely for now, let it default or try different params
        // Some users report 500 when "stream": false is used with complex prompts on low-memory envs
        // Let's try just model and prompt
        let payload = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "num_ctx": 2048,
                "temperature": 0.0
            }
        });

        // Debug print
        // println!("DEBUG: Sending payload to {}", url);

        match self.client.post(&url).json(&payload).send().await {
            Ok(res) => {
                if res.status().is_success() {
                    if let Ok(json) = res.json::<serde_json::Value>().await {
                        return json["response"].as_str().unwrap_or("EMPTY").to_string();
                    }
                } else {
                    println!("    [!] AI Server Error: {} - Check Ollama logs", res.status());
                    // If 500, it might be the prompt length or model state.
                }
            }
            Err(e) => println!("    [!] Request Failed: {}", e),
        }
        "OFFLINE".to_string()
    }
}
