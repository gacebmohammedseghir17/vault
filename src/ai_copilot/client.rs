use reqwest::blocking::Client;
use serde_json::json;
use std::env;
use std::time::Duration;

pub struct AiCopilot {
    api_key: String,
    client: Client,
}

impl AiCopilot {
    /// Initializes the AiCopilot by reading the OPENROUTER_API_KEY from the environment.
    /// Sets a strict 30000ms timeout to ensure the EDR never hangs.
    pub fn new() -> Result<Self, String> {
        dotenvy::dotenv().ok();
        let api_key = env::var("OPENROUTER_API_KEY")
            .map_err(|_| "OPENROUTER_API_KEY environment variable not set".to_string())?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_default();

        Ok(Self { api_key, client })
    }

    /// Sends a prompt to the OpenRouter API using the deepseek/deepseek-v4-flash model.
    pub fn analyze_threat(&self, prompt: &str) -> Result<String, String> {
        let url = "https://openrouter.ai/api/v1/chat/completions";

        let body = json!({
            "model": "deepseek/deepseek-v4-flash",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        });

        let response = self.client.post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if response.status().is_success() {
            let resp_json: serde_json::Value = response.json()
                .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

            if let Some(content) = resp_json["choices"][0]["message"]["content"].as_str() {
                Ok(content.to_string())
            } else {
                Err("Unexpected JSON structure in response".to_string())
            }
        } else {
            Err(format!("API error: {}", response.status()))
        }
    }
}
