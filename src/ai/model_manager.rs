//! AI model management for Ollama integration
//! Handles model lifecycle, performance monitoring, and optimization

use super::{AIConfig, AIError, AIResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model name
    pub name: String,
    /// Model size in bytes
    pub size: u64,
    /// Model digest/hash
    pub digest: String,
    /// Last modified timestamp
    pub modified_at: String,
    /// Model family (e.g., llama, mistral)
    pub family: String,
    /// Model parameters count
    pub parameters: Option<String>,
    /// Quantization level
    pub quantization: Option<String>,
}

/// Model performance metrics
#[derive(Debug, Clone, Default)]
pub struct ModelMetrics {
    /// Total requests processed
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Average tokens per second
    pub avg_tokens_per_second: f64,
    /// Memory usage in MB
    pub memory_usage_mb: f64,
    /// Last used timestamp
    pub last_used: Option<Instant>,
    /// Error rate (0.0 to 1.0)
    pub error_rate: f32,
}

/// Model status
#[derive(Debug, Clone, PartialEq)]
pub enum ModelStatus {
    /// Model is available and ready
    Available,
    /// Model is currently loading
    Loading,
    /// Model is not available
    Unavailable,
    /// Model has errors
    Error(String),
}

/// Model recommendation based on analysis type
#[derive(Debug, Clone)]
pub struct ModelRecommendation {
    /// Recommended model name
    pub model_name: String,
    /// Confidence in recommendation (0.0 to 1.0)
    pub confidence: f32,
    /// Reason for recommendation
    pub reason: String,
    /// Expected performance characteristics
    pub performance_estimate: PerformanceEstimate,
}

/// Performance estimate for model
#[derive(Debug, Clone)]
pub struct PerformanceEstimate {
    /// Estimated response time in milliseconds
    pub estimated_response_time_ms: u64,
    /// Estimated accuracy for the task
    pub estimated_accuracy: f32,
    /// Resource requirements
    pub resource_requirements: ResourceRequirements,
}

/// Resource requirements for model
#[derive(Debug, Clone)]
pub struct ResourceRequirements {
    /// Memory requirement in MB
    pub memory_mb: u64,
    /// CPU cores recommended
    pub cpu_cores: u32,
    /// GPU memory requirement in MB (if applicable)
    pub gpu_memory_mb: Option<u64>,
}

/// Model manager for Ollama integration
pub struct ModelManager {
    /// HTTP client for Ollama API
    client: Client,
    /// Configuration
    config: AIConfig,
    /// Available models cache
    models_cache: Arc<RwLock<HashMap<String, ModelInfo>>>,
    /// Model performance metrics
    metrics: Arc<RwLock<HashMap<String, ModelMetrics>>>,
    /// Model status tracking
    status_cache: Arc<RwLock<HashMap<String, ModelStatus>>>,
    /// Model recommendations cache
    recommendations_cache: Arc<RwLock<HashMap<String, Vec<ModelRecommendation>>>>,
}

impl ModelManager {
    /// Create new model manager
    pub fn new(config: AIConfig) -> AIResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| AIError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client,
            config,
            models_cache: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            status_cache: Arc::new(RwLock::new(HashMap::new())),
            recommendations_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Refresh available models from Ollama server
    pub async fn refresh_models(&self) -> AIResult<Vec<ModelInfo>> {
        debug!("Refreshing models from Ollama server");
        
        let url = format!("{}/api/tags", self.config.ollama_url);
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| AIError::ConnectionError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AIError::HttpError(format!("HTTP {}", response.status())));
        }

        #[derive(Deserialize)]
        struct OllamaModelsResponse {
            models: Vec<OllamaModelInfo>,
        }

        #[derive(Deserialize)]
        struct OllamaModelInfo {
            name: String,
            size: u64,
            digest: String,
            modified_at: String,
            details: Option<OllamaModelDetails>,
        }

        #[derive(Deserialize)]
        struct OllamaModelDetails {
            family: Option<String>,
            parameter_size: Option<String>,
            quantization_level: Option<String>,
        }

        let ollama_response: OllamaModelsResponse = response
            .json()
            .await
            .map_err(|e| AIError::HttpError(e.to_string()))?;

        let mut models = Vec::new();
        let mut models_cache = self.models_cache.write().await;
        models_cache.clear();

        for ollama_model in ollama_response.models {
            let model_info = ModelInfo {
                name: ollama_model.name.clone(),
                size: ollama_model.size,
                digest: ollama_model.digest,
                modified_at: ollama_model.modified_at,
                family: ollama_model.details.as_ref()
                    .and_then(|d| d.family.clone())
                    .unwrap_or_else(|| self.extract_family_from_name(&ollama_model.name)),
                parameters: ollama_model.details.as_ref()
                    .and_then(|d| d.parameter_size.clone()),
                quantization: ollama_model.details.as_ref()
                    .and_then(|d| d.quantization_level.clone()),
            };

            models_cache.insert(model_info.name.clone(), model_info.clone());
            models.push(model_info);
        }

        info!("Refreshed {} models from Ollama server", models.len());
        Ok(models)
    }

    /// Get available models (from cache or refresh)
    pub async fn get_available_models(&self) -> AIResult<Vec<ModelInfo>> {
        let models_cache = self.models_cache.read().await;
        
        if models_cache.is_empty() {
            drop(models_cache);
            self.refresh_models().await
        } else {
            Ok(models_cache.values().cloned().collect())
        }
    }

    /// Get model information by name
    pub async fn get_model_info(&self, model_name: &str) -> Option<ModelInfo> {
        let models_cache = self.models_cache.read().await;
        models_cache.get(model_name).cloned()
    }

    /// Check model status
    pub async fn check_model_status(&self, model_name: &str) -> ModelStatus {
        // Check cache first
        {
            let status_cache = self.status_cache.read().await;
            if let Some(status) = status_cache.get(model_name) {
                return status.clone();
            }
        }

        // Check with Ollama server
        let status = self.probe_model_status(model_name).await;
        
        // Update cache
        {
            let mut status_cache = self.status_cache.write().await;
            status_cache.insert(model_name.to_string(), status.clone());
        }

        status
    }

    /// Probe model status from Ollama server
    async fn probe_model_status(&self, model_name: &str) -> ModelStatus {
        let url = format!("{}/api/show", self.config.ollama_url);
        
        #[derive(Serialize)]
        struct ShowRequest {
            name: String,
        }

        let request = ShowRequest {
            name: model_name.to_string(),
        };

        match self.client.post(&url).json(&request).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    ModelStatus::Available
                } else if response.status().as_u16() == 404 {
                    ModelStatus::Unavailable
                } else {
                    ModelStatus::Error(format!("HTTP {}", response.status()))
                }
            }
            Err(e) => ModelStatus::Error(e.to_string()),
        }
    }

    /// Get model recommendations for analysis type
    pub async fn get_model_recommendations(&self, analysis_type: &str) -> AIResult<Vec<ModelRecommendation>> {
        // Check cache first
        {
            let recommendations_cache = self.recommendations_cache.read().await;
            if let Some(recommendations) = recommendations_cache.get(analysis_type) {
                return Ok(recommendations.clone());
            }
        }

        // Generate recommendations
        let recommendations = self.generate_model_recommendations(analysis_type).await?;
        
        // Update cache
        {
            let mut recommendations_cache = self.recommendations_cache.write().await;
            recommendations_cache.insert(analysis_type.to_string(), recommendations.clone());
        }

        Ok(recommendations)
    }

    /// Generate model recommendations based on analysis type
    async fn generate_model_recommendations(&self, analysis_type: &str) -> AIResult<Vec<ModelRecommendation>> {
        let available_models = self.get_available_models().await?;
        let mut recommendations = Vec::new();

        for model in available_models {
            let recommendation = self.evaluate_model_for_analysis(&model, analysis_type).await;
            if recommendation.confidence > 0.3 {
                recommendations.push(recommendation);
            }
        }

        // Sort by confidence (highest first)
        recommendations.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        Ok(recommendations)
    }

    /// Evaluate model suitability for analysis type
    async fn evaluate_model_for_analysis(&self, model: &ModelInfo, analysis_type: &str) -> ModelRecommendation {
        let mut confidence: f32 = 0.5; // Base confidence
        let mut reason_parts = Vec::new();

        // Evaluate based on model family
        match model.family.as_str() {
            "llama" => {
                confidence += 0.2;
                reason_parts.push("Llama models excel at reasoning tasks");
            }
            "mistral" => {
                confidence += 0.15;
                reason_parts.push("Mistral models are efficient and accurate");
            }
            "codellama" => {
                if analysis_type.contains("code") || analysis_type.contains("disassembly") {
                    confidence += 0.3;
                    reason_parts.push("CodeLlama specialized for code analysis");
                }
            }
            _ => {}
        }

        // Evaluate based on model size
        let size_gb = model.size as f64 / (1024.0 * 1024.0 * 1024.0);
        match size_gb {
            size if size >= 10.0 => {
                confidence += 0.1;
                reason_parts.push("Large model with high capability");
            }
            size if size >= 5.0 => {
                confidence += 0.05;
                reason_parts.push("Medium-sized model with good balance");
            }
            _ => {
                reason_parts.push("Compact model for fast inference");
            }
        }

        // Evaluate based on analysis type
        match analysis_type {
            "malware_classification" => {
                if model.name.contains("instruct") {
                    confidence += 0.1;
                    reason_parts.push("Instruction-tuned for classification tasks");
                }
            }
            "yara_rule_generation" => {
                if model.name.contains("code") {
                    confidence += 0.15;
                    reason_parts.push("Code-focused model for rule generation");
                }
            }
            "behavioral_analysis" => {
                confidence += 0.05; // Most models can handle this
                reason_parts.push("Suitable for behavioral pattern analysis");
            }
            _ => {}
        }

        // Get performance metrics if available
        let metrics = {
            let metrics_cache = self.metrics.read().await;
            metrics_cache.get(&model.name).cloned()
        };

        let performance_estimate = if let Some(metrics) = metrics {
            // Adjust confidence based on historical performance
            if metrics.error_rate < 0.1 {
                confidence += 0.1;
                reason_parts.push("Low error rate in historical usage");
            }

            PerformanceEstimate {
                estimated_response_time_ms: metrics.avg_response_time_ms as u64,
                estimated_accuracy: 1.0 - metrics.error_rate,
                resource_requirements: self.estimate_resource_requirements(&model),
            }
        } else {
            PerformanceEstimate {
                estimated_response_time_ms: self.estimate_response_time(&model),
                estimated_accuracy: 0.8, // Default estimate
                resource_requirements: self.estimate_resource_requirements(&model),
            }
        };

        ModelRecommendation {
            model_name: model.name.clone(),
            confidence: confidence.min(1.0),
            reason: reason_parts.join("; "),
            performance_estimate,
        }
    }

    /// Estimate response time for model
    fn estimate_response_time(&self, model: &ModelInfo) -> u64 {
        let size_gb = model.size as f64 / (1024.0 * 1024.0 * 1024.0);
        
        // Base time + size factor
        let base_time = 1000; // 1 second base
        let size_factor = (size_gb * 500.0) as u64; // 500ms per GB
        
        base_time + size_factor
    }

    /// Estimate resource requirements for model
    fn estimate_resource_requirements(&self, model: &ModelInfo) -> ResourceRequirements {
        let size_gb = model.size as f64 / (1024.0 * 1024.0 * 1024.0);
        
        ResourceRequirements {
            memory_mb: ((size_gb * 1.5) * 1024.0) as u64, // 1.5x model size for overhead
            cpu_cores: if size_gb > 10.0 { 4 } else { 2 },
            gpu_memory_mb: if size_gb > 5.0 { Some((size_gb * 1024.0) as u64) } else { None },
        }
    }

    /// Record model usage metrics
    pub async fn record_usage(&self, model_name: &str, response_time_ms: u64, success: bool, tokens_per_second: Option<f64>) {
        let mut metrics_cache = self.metrics.write().await;
        let metrics = metrics_cache.entry(model_name.to_string()).or_insert_with(ModelMetrics::default);

        metrics.total_requests += 1;
        if success {
            metrics.successful_requests += 1;
        } else {
            metrics.failed_requests += 1;
        }

        // Update average response time
        let total_time = metrics.avg_response_time_ms * (metrics.total_requests - 1) as f64 + response_time_ms as f64;
        metrics.avg_response_time_ms = total_time / metrics.total_requests as f64;

        // Update tokens per second if provided
        if let Some(tps) = tokens_per_second {
            let total_tps = metrics.avg_tokens_per_second * (metrics.successful_requests - 1) as f64 + tps;
            metrics.avg_tokens_per_second = total_tps / metrics.successful_requests as f64;
        }

        // Update error rate
        metrics.error_rate = metrics.failed_requests as f32 / metrics.total_requests as f32;

        // Update last used timestamp
        metrics.last_used = Some(Instant::now());

        debug!("Updated metrics for model {}: {} requests, {:.2}% error rate", 
               model_name, metrics.total_requests, metrics.error_rate * 100.0);
    }

    /// Get model performance metrics
    pub async fn get_model_metrics(&self, model_name: &str) -> Option<ModelMetrics> {
        let metrics_cache = self.metrics.read().await;
        metrics_cache.get(model_name).cloned()
    }

    /// Get all model metrics
    pub async fn get_all_metrics(&self) -> HashMap<String, ModelMetrics> {
        let metrics_cache = self.metrics.read().await;
        metrics_cache.clone()
    }

    /// Extract model family from name
    fn extract_family_from_name(&self, name: &str) -> String {
        let name_lower = name.to_lowercase();
        
        if name_lower.contains("codellama") {
            "codellama".to_string()
        } else if name_lower.contains("llama") {
            "llama".to_string()
        } else if name_lower.contains("mistral") {
            "mistral".to_string()
        } else if name_lower.contains("gemma") {
            "gemma".to_string()
        } else if name_lower.contains("phi") {
            "phi".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Clear all caches
    pub async fn clear_caches(&self) {
        let mut models_cache = self.models_cache.write().await;
        let mut status_cache = self.status_cache.write().await;
        let mut recommendations_cache = self.recommendations_cache.write().await;
        
        models_cache.clear();
        status_cache.clear();
        recommendations_cache.clear();
        
        info!("Cleared all model manager caches");
    }

    /// Get best model for analysis type
    pub async fn get_best_model(&self, analysis_type: &str) -> AIResult<Option<String>> {
        let recommendations = self.get_model_recommendations(analysis_type).await?;
        
        // Return the highest confidence recommendation that's available
        for recommendation in recommendations {
            let status = self.check_model_status(&recommendation.model_name).await;
            if status == ModelStatus::Available {
                return Ok(Some(recommendation.model_name));
            }
        }

        // Fallback to default model if no recommendations are available
        let default_status = self.check_model_status(&self.config.default_model).await;
        if default_status == ModelStatus::Available {
            Ok(Some(self.config.default_model.clone()))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_manager_creation() {
        let config = AIConfig::default();
        let manager = ModelManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_family_extraction() {
        let config = AIConfig::default();
        let manager = ModelManager::new(config).unwrap();
        
        assert_eq!(manager.extract_family_from_name("llama3.2:3b"), "llama");
        assert_eq!(manager.extract_family_from_name("mistral:7b"), "mistral");
        assert_eq!(manager.extract_family_from_name("codellama:13b"), "codellama");
        assert_eq!(manager.extract_family_from_name("unknown-model"), "unknown");
    }

    #[test]
    fn test_resource_estimation() {
        let config = AIConfig::default();
        let manager = ModelManager::new(config).unwrap();
        
        let model = ModelInfo {
            name: "test-model".to_string(),
            size: 5 * 1024 * 1024 * 1024, // 5GB
            digest: "test".to_string(),
            modified_at: "2024-01-01".to_string(),
            family: "llama".to_string(),
            parameters: None,
            quantization: None,
        };
        
        let requirements = manager.estimate_resource_requirements(&model);
        assert_eq!(requirements.memory_mb, 7680); // 5GB * 1.5 * 1024
        assert_eq!(requirements.cpu_cores, 2);
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let config = AIConfig::default();
        let manager = ModelManager::new(config).unwrap();
        
        manager.record_usage("test-model", 1000, true, Some(50.0)).await;
        
        let metrics = manager.get_model_metrics("test-model").await.unwrap();
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.avg_response_time_ms, 1000.0);
        assert_eq!(metrics.avg_tokens_per_second, 50.0);
    }
}
