//! Ollama client for local AI integration
//! Provides REST API client for communicating with local Ollama server

use super::{AIConfig, AnalysisRequest, AnalysisResult, AnalysisType, AnalysisInput, Finding, Severity, ThreatClassification, AIError, AIResult, AnalysisStats};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;


/// Ollama API request structure
#[derive(Debug, Clone, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: Option<OllamaOptions>,
}

/// Ollama API response structure
#[derive(Debug, Clone, Deserialize)]
struct OllamaResponse {
    response: String,
    done: bool,
    #[serde(default)]
    total_duration: Option<u64>,
    #[serde(default)]
    load_duration: Option<u64>,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

/// Ollama model information
#[derive(Debug, Clone, Deserialize)]
struct OllamaModel {
    name: String,
    size: u64,
    digest: String,
    modified_at: String,
}

/// Ollama models list response
#[derive(Debug, Clone, Deserialize)]
struct OllamaModelsResponse {
    models: Vec<OllamaModel>,
}

/// Ollama request options
#[derive(Debug, Clone, Serialize)]
struct OllamaOptions {
    temperature: f32,
    top_p: f32,
    top_k: i32,
    num_predict: i32,
}

impl Default for OllamaOptions {
    fn default() -> Self {
        Self {
            temperature: 0.1, // Low temperature for consistent analysis
            top_p: 0.9,
            top_k: 40,
            num_predict: 2048,
        }
    }
}

/// Ollama client for AI analysis
pub struct OllamaClient {
    /// HTTP client
    client: Client,
    /// Configuration
    config: AIConfig,
    /// Analysis statistics
    stats: Arc<RwLock<AnalysisStats>>,
    /// Response cache
    cache: Arc<RwLock<HashMap<String, (AnalysisResult, Instant)>>>,
}

impl OllamaClient {
    /// Create new Ollama client
    pub fn new(config: AIConfig) -> AIResult<Self> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| AIError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client,
            config,
            stats: Arc::new(RwLock::new(AnalysisStats::default())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if Ollama server is available
    pub async fn is_available(&self) -> bool {
        match self.client.get(&format!("{}/api/tags", self.config.ollama_url)).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Get available models from Ollama server
    pub async fn get_available_models(&self) -> AIResult<Vec<String>> {
        let url = format!("{}/api/tags", self.config.ollama_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| AIError::ConnectionError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AIError::HttpError(format!("HTTP {}", response.status())));
        }

        let models_response: OllamaModelsResponse = response
            .json()
            .await
            .map_err(|e| AIError::HttpError(e.to_string()))?;

        Ok(models_response.models.into_iter().map(|m| m.name).collect())
    }

    /// Perform AI analysis
    pub async fn analyze(&self, request: AnalysisRequest) -> AIResult<AnalysisResult> {
        let start_time = Instant::now();
        
        // Check cache first
        if self.config.enable_cache {
            let cache_key = self.generate_cache_key(&request);
            if let Some(cached_result) = self.get_cached_result(&cache_key).await {
                self.update_stats(true, start_time.elapsed().as_millis() as u64, &request.analysis_type).await;
                return Ok(cached_result);
            }
        }

        // Generate prompt based on analysis type and input
        let prompt = self.generate_prompt(&request)?;
        let model = request.model.clone().unwrap_or_else(|| self.config.default_model.clone());

        // Make request to Ollama
        let ollama_request = OllamaRequest {
            model: model.clone(),
            prompt,
            stream: false,
            options: Some(OllamaOptions::default()),
        };

        let mut retries = 0;
        let mut last_error = None;

        while retries < self.config.max_retries {
            match self.make_ollama_request(&ollama_request).await {
                Ok(response) => {
                    let analysis_result = self.parse_analysis_response(&request, &response, &model, start_time)?;
                    
                    // Cache the result
                    if self.config.enable_cache {
                        let cache_key = self.generate_cache_key(&request);
                        self.cache_result(cache_key, analysis_result.clone()).await;
                    }

                    self.update_stats(true, start_time.elapsed().as_millis() as u64, &request.analysis_type).await;
                    return Ok(analysis_result);
                }
                Err(e) => {
                    last_error = Some(e);
                    retries += 1;
                    if retries < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(1000 * retries as u64)).await;
                    }
                }
            }
        }

        self.update_stats(false, start_time.elapsed().as_millis() as u64, &request.analysis_type).await;
        Err(last_error.unwrap_or(AIError::AnalysisError("Max retries exceeded".to_string())))
    }

    /// Make request to Ollama API
    async fn make_ollama_request(&self, request: &OllamaRequest) -> AIResult<OllamaResponse> {
        let url = format!("{}/api/generate", self.config.ollama_url);
        
        let response = self.client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|e| AIError::ConnectionError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AIError::HttpError(format!("HTTP {}: {}", response.status(), response.text().await.unwrap_or_default())));
        }

        let ollama_response: OllamaResponse = response
            .json()
            .await
            .map_err(|e| AIError::HttpError(e.to_string()))?;

        Ok(ollama_response)
    }

    /// Generate prompt based on analysis request
    fn generate_prompt(&self, request: &AnalysisRequest) -> AIResult<String> {
        match &request.analysis_type {
            AnalysisType::MalwareClassification => {
                self.generate_malware_classification_prompt(&request.input_data)
            }
            AnalysisType::YaraRuleGeneration => {
                self.generate_yara_rule_prompt(&request.input_data)
            }
            AnalysisType::BehavioralAnalysis => {
                self.generate_behavioral_analysis_prompt(&request.input_data)
            }
            AnalysisType::SimilarityAnalysis => {
                self.generate_similarity_analysis_prompt(&request.input_data)
            }
            AnalysisType::ThreatCorrelation => {
                self.generate_threat_correlation_prompt(&request.input_data)
            }
            AnalysisType::Custom(analysis_name) => {
                self.generate_custom_analysis_prompt(&request.input_data, analysis_name)
            }
        }
    }

    /// Generate malware classification prompt
    fn generate_malware_classification_prompt(&self, input: &AnalysisInput) -> AIResult<String> {
        let base_prompt = "You are an expert malware analyst. Analyze the provided data and classify the malware. Provide your response in JSON format with the following structure:\n\n{\n  \"confidence\": 0.85,\n  \"findings\": [\n    {\n      \"category\": \"malware_family\",\n      \"severity\": \"High\",\n      \"description\": \"Detected malware family\",\n      \"confidence\": 0.9,\n      \"evidence\": [\"evidence1\", \"evidence2\"],\n      \"recommendations\": [\"recommendation1\"]\n    }\n  ],\n  \"threat_classification\": {\n    \"family\": \"Trojan\",\n    \"variant\": \"Banker\",\n    \"malware_type\": [\"Banking Trojan\"],\n    \"attack_techniques\": [\"T1055\", \"T1082\"],\n    \"confidence\": 0.85\n  }\n}\n\nData to analyze:\n";

        match input {
            AnalysisInput::BinaryData { data, filename, file_type } => {
                Ok(format!("{}\nFilename: {}\nFile Type: {}\nBinary Data (hex): {}\n", 
                    base_prompt, filename, file_type, hex::encode(&data[..data.len().min(1024)])))
            }
            AnalysisInput::DisassemblyCode { instructions, architecture, entry_point } => {
                Ok(format!("{}\nArchitecture: {}\nEntry Point: 0x{:x}\nDisassembly:\n{}\n", 
                    base_prompt, architecture, entry_point, instructions.join("\n")))
            }
            AnalysisInput::TextData { content, data_type } => {
                Ok(format!("{}\nData Type: {}\nContent:\n{}\n", base_prompt, data_type, content))
            }
            _ => Err(AIError::InvalidInput("Unsupported input type for malware classification".to_string())),
        }
    }

    /// Generate YARA rule generation prompt
    fn generate_yara_rule_prompt(&self, input: &AnalysisInput) -> AIResult<String> {
        let base_prompt = "You are an expert YARA rule writer. Generate high-quality YARA rules based on the provided malware sample. Provide your response in JSON format:\n\n{\n  \"confidence\": 0.9,\n  \"yara_rules\": [\n    \"rule MalwareName { strings: $s1 = \\\"pattern\\\" condition: $s1 }\"\n  ],\n  \"findings\": [\n    {\n      \"category\": \"yara_generation\",\n      \"severity\": \"Medium\",\n      \"description\": \"Generated YARA rule\",\n      \"confidence\": 0.9,\n      \"evidence\": [\"pattern found\"],\n      \"recommendations\": [\"Test rule thoroughly\"]\n    }\n  ]\n}\n\nSample to analyze:\n";

        match input {
            AnalysisInput::BinaryData { data, filename, file_type } => {
                Ok(format!("{}\nFilename: {}\nFile Type: {}\nBinary Data (hex): {}\n", 
                    base_prompt, filename, file_type, hex::encode(&data[..data.len().min(2048)])))
            }
            AnalysisInput::DisassemblyCode { instructions, architecture, entry_point } => {
                Ok(format!("{}\nArchitecture: {}\nEntry Point: 0x{:x}\nDisassembly:\n{}\n", 
                    base_prompt, architecture, entry_point, instructions.join("\n")))
            }
            _ => Err(AIError::InvalidInput("Unsupported input type for YARA rule generation".to_string())),
        }
    }

    /// Generate behavioral analysis prompt
    fn generate_behavioral_analysis_prompt(&self, input: &AnalysisInput) -> AIResult<String> {
        let base_prompt = "You are an expert in malware behavioral analysis. Analyze the provided behavioral data and identify malicious patterns. Provide your response in JSON format:\n\n{\n  \"confidence\": 0.8,\n  \"findings\": [\n    {\n      \"category\": \"behavioral_pattern\",\n      \"severity\": \"High\",\n      \"description\": \"Suspicious behavior detected\",\n      \"confidence\": 0.85,\n      \"evidence\": [\"behavior1\", \"behavior2\"],\n      \"recommendations\": [\"Monitor process\"]\n    }\n  ]\n}\n\nBehavioral data:\n";

        match input {
            AnalysisInput::BehavioralData { indicators, timeline, process_info } => {
                Ok(format!("{}\nIndicators: {:?}\nTimeline: {:?}\nProcess Info: {:?}\n", 
                    base_prompt, indicators, timeline, process_info))
            }
            AnalysisInput::NetworkTraffic { packets, protocol, flow_info } => {
                Ok(format!("{}\nProtocol: {}\nPackets: {:?}\nFlow Info: {:?}\n", 
                    base_prompt, protocol, packets, flow_info))
            }
            _ => Err(AIError::InvalidInput("Unsupported input type for behavioral analysis".to_string())),
        }
    }

    /// Generate similarity analysis prompt
    fn generate_similarity_analysis_prompt(&self, input: &AnalysisInput) -> AIResult<String> {
        let base_prompt = "You are an expert in malware similarity analysis. Compare the provided sample with known malware families and identify similarities. Provide your response in JSON format:\n\n{\n  \"confidence\": 0.75,\n  \"findings\": [\n    {\n      \"category\": \"similarity\",\n      \"severity\": \"Medium\",\n      \"description\": \"Similar to known malware family\",\n      \"confidence\": 0.8,\n      \"evidence\": [\"shared code patterns\"],\n      \"recommendations\": [\"Further analysis needed\"]\n    }\n  ]\n}\n\nSample data:\n";

        match input {
            AnalysisInput::BinaryData { data, filename, file_type } => {
                Ok(format!("{}\nFilename: {}\nFile Type: {}\nBinary Data (hex): {}\n", 
                    base_prompt, filename, file_type, hex::encode(&data[..data.len().min(1024)])))
            }
            AnalysisInput::DisassemblyCode { instructions, architecture, entry_point } => {
                Ok(format!("{}\nArchitecture: {}\nEntry Point: 0x{:x}\nDisassembly:\n{}\n", 
                    base_prompt, architecture, entry_point, instructions.join("\n")))
            }
            _ => Err(AIError::InvalidInput("Unsupported input type for similarity analysis".to_string())),
        }
    }

    /// Generate threat correlation prompt
    fn generate_threat_correlation_prompt(&self, input: &AnalysisInput) -> AIResult<String> {
        let base_prompt = "You are an expert in threat intelligence correlation. Analyze the provided data and correlate with known threat actors and campaigns. Provide your response in JSON format:\n\n{\n  \"confidence\": 0.7,\n  \"findings\": [\n    {\n      \"category\": \"threat_correlation\",\n      \"severity\": \"High\",\n      \"description\": \"Correlated with known threat actor\",\n      \"confidence\": 0.75,\n      \"evidence\": [\"TTPs match\"],\n      \"recommendations\": [\"Monitor for campaign indicators\"]\n    }\n  ]\n}\n\nThreat data:\n";

        match input {
            AnalysisInput::TextData { content, data_type } => {
                Ok(format!("{}\nData Type: {}\nContent:\n{}\n", base_prompt, data_type, content))
            }
            AnalysisInput::BehavioralData { indicators, timeline, process_info } => {
                Ok(format!("{}\nIndicators: {:?}\nTimeline: {:?}\nProcess Info: {:?}\n", 
                    base_prompt, indicators, timeline, process_info))
            }
            _ => Err(AIError::InvalidInput("Unsupported input type for threat correlation".to_string())),
        }
    }

    /// Generate custom analysis prompt
    fn generate_custom_analysis_prompt(&self, input: &AnalysisInput, analysis_name: &str) -> AIResult<String> {
        let base_prompt = format!("You are an expert malware analyst performing custom analysis: {}. Analyze the provided data and provide insights. Provide your response in JSON format:\n\n{{\n  \"confidence\": 0.8,\n  \"findings\": [\n    {{\n      \"category\": \"custom_analysis\",\n      \"severity\": \"Medium\",\n      \"description\": \"Custom analysis result\",\n      \"confidence\": 0.8,\n      \"evidence\": [\"finding1\"],\n      \"recommendations\": [\"recommendation1\"]\n    }}\n  ]\n}}\n\nData to analyze:\n", analysis_name);

        match input {
            AnalysisInput::TextData { content, data_type } => {
                Ok(format!("{}\nData Type: {}\nContent:\n{}\n", base_prompt, data_type, content))
            }
            AnalysisInput::BinaryData { data, filename, file_type } => {
                Ok(format!("{}\nFilename: {}\nFile Type: {}\nBinary Data (hex): {}\n", 
                    base_prompt, filename, file_type, hex::encode(&data[..data.len().min(1024)])))
            }
            _ => Ok(format!("{}\nInput: {:?}\n", base_prompt, input)),
        }
    }

    /// Parse analysis response from Ollama
    fn parse_analysis_response(
        &self,
        request: &AnalysisRequest,
        response: &OllamaResponse,
        model: &str,
        start_time: Instant,
    ) -> AIResult<AnalysisResult> {
        // Try to parse JSON response; support fenced blocks and repair
        let raw = response.response.trim();
        let fenced_json = if let Some(start) = raw.find("```json") {
            if let Some(end) = raw[start + 7..].find("```") { // 7 = len("```json")
                let body = &raw[start + 7..start + 7 + end];
                Some(body.trim())
            } else { None }
        } else { None };

        let parsed_response: serde_json::Value = match fenced_json {
            Some(body) => serde_json::from_str(body).unwrap_or_else(|_| serde_json::json!({
                "confidence": 0.5,
                "findings": [{
                    "category": "ai_analysis",
                    "severity": "Medium",
                    "description": raw,
                    "confidence": 0.5,
                    "evidence": [],
                    "recommendations": []
                }]
            })),
            None => serde_json::from_str(raw).unwrap_or_else(|_| serde_json::json!({
                "confidence": 0.5,
                "findings": [{
                    "category": "ai_analysis",
                    "severity": "Medium",
                    "description": raw,
                    "confidence": 0.5,
                    "evidence": [],
                    "recommendations": []
                }]
            })),
        };

        let confidence = parsed_response["confidence"].as_f64().unwrap_or(0.5) as f32;
        
        let findings: Vec<Finding> = parsed_response["findings"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|f| Finding {
                category: f["category"].as_str().unwrap_or("unknown").to_string(),
                severity: match f["severity"].as_str().unwrap_or("Medium") {
                    "Critical" => Severity::Critical,
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    "Low" => Severity::Low,
                    _ => Severity::Info,
                },
                description: f["description"].as_str().unwrap_or("").to_string(),
                confidence: f["confidence"].as_f64().unwrap_or(0.5) as f32,
                evidence: f["evidence"].as_array().unwrap_or(&vec![])
                    .iter().map(|e| e.as_str().unwrap_or("").to_string()).collect(),
                recommendations: f["recommendations"].as_array().unwrap_or(&vec![])
                    .iter().map(|r| r.as_str().unwrap_or("").to_string()).collect(),
            })
            .collect();

        let yara_rules = parsed_response["yara_rules"]
            .as_array()
            .map(|rules| rules.iter().map(|r| r.as_str().unwrap_or("").to_string()).collect());

        let threat_classification = parsed_response["threat_classification"]
            .as_object()
            .map(|tc| ThreatClassification {
                family: tc.get("family").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                variant: tc.get("variant").and_then(|v| v.as_str()).map(|s| s.to_string()),
                malware_type: tc.get("malware_type").and_then(|v| v.as_array()).unwrap_or(&vec![])
                    .iter().map(|mt| mt.as_str().unwrap_or("").to_string()).collect(),
                attack_techniques: tc.get("attack_techniques").and_then(|v| v.as_array()).unwrap_or(&vec![])
                    .iter().map(|at| at.as_str().unwrap_or("").to_string()).collect(),
                confidence: tc.get("confidence").and_then(|v| v.as_f64()).unwrap_or(confidence as f64) as f32,
            });

        Ok(AnalysisResult {
            analysis_type: request.analysis_type.clone(),
            confidence,
            findings,
            yara_rules,
            threat_classification,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
            model_used: model.to_string(),
            metadata: HashMap::new(),
        })
    }

    /// Generate cache key for request
    fn generate_cache_key(&self, request: &AnalysisRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        format!("{:?}", request).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Get cached result
    async fn get_cached_result(&self, cache_key: &str) -> Option<AnalysisResult> {
        let cache = self.cache.read().await;
        if let Some((result, timestamp)) = cache.get(cache_key) {
            if timestamp.elapsed().as_secs() < self.config.cache_ttl {
                return Some(result.clone());
            }
        }
        None
    }

    /// Cache analysis result
    async fn cache_result(&self, cache_key: String, result: AnalysisResult) {
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, (result, Instant::now()));
        
        // Clean expired entries
        let now = Instant::now();
        cache.retain(|_, (_, timestamp)| now.duration_since(*timestamp).as_secs() < self.config.cache_ttl);
    }

    /// Update analysis statistics
    async fn update_stats(&self, success: bool, processing_time: u64, analysis_type: &AnalysisType) {
        let mut stats = self.stats.write().await;
        stats.total_analyses += 1;
        
        if success {
            stats.successful_analyses += 1;
        } else {
            stats.failed_analyses += 1;
        }

        // Update average processing time
        let total_time = stats.avg_processing_time_ms * (stats.total_analyses - 1) as f64 + processing_time as f64;
        stats.avg_processing_time_ms = total_time / stats.total_analyses as f64;

        // Update analysis type statistics
        let type_key = format!("{:?}", analysis_type);
        *stats.analysis_type_stats.entry(type_key).or_insert(0) += 1;
    }

    /// Get analysis statistics
    pub async fn get_statistics(&self) -> AnalysisStats {
        self.stats.read().await.clone()
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_client_creation() {
        let config = AIConfig::default();
        let client = OllamaClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_prompt_generation() {
        let config = AIConfig::default();
        let client = OllamaClient::new(config).unwrap();
        
        let input = AnalysisInput::TextData {
            content: "test content".to_string(),
            data_type: "text".to_string(),
        };
        
        let prompt = client.generate_malware_classification_prompt(&input);
        assert!(prompt.is_ok());
        assert!(prompt.unwrap().contains("test content"));
    }

    #[test]
    fn test_cache_key_generation() {
        let config = AIConfig::default();
        let client = OllamaClient::new(config).unwrap();
        
        let request = AnalysisRequest {
            analysis_type: AnalysisType::MalwareClassification,
            input_data: AnalysisInput::TextData {
                content: "test".to_string(),
                data_type: "text".to_string(),
            },
            model: None,
            context: HashMap::new(),
        };
        
        let key1 = client.generate_cache_key(&request);
        let key2 = client.generate_cache_key(&request);
        assert_eq!(key1, key2);
    }
}
