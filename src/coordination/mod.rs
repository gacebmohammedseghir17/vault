//! Multi-Agent Coordination System
//!
//! This module implements a distributed coordination system for ERDPS agents,
//! enabling secure communication, task distribution, and collaborative threat detection.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::time::Duration;

pub mod communication;
pub mod discovery;
pub mod consensus;
pub mod load_balancer;
pub mod security;
pub mod synchronization;

/// Multi-agent coordination engine
#[derive(Debug)]
pub struct AgentCoordinator {
    config: CoordinationConfig,
    agent_id: Uuid,
    communication_manager: Arc<communication::CommunicationManager>,
    discovery_service: Arc<discovery::DiscoveryService>,
    consensus_service: Arc<consensus::ConsensusService>,
    load_balancer: Arc<load_balancer::LoadBalancer>,
    security_manager: Arc<security::SecurityManager>,
    sync_manager: Arc<synchronization::SynchronizationManager>,
    agent_registry: Arc<RwLock<AgentRegistry>>,
    task_queue: Arc<RwLock<TaskQueue>>,
    coordination_cache: Arc<RwLock<CoordinationCache>>,
    statistics: Arc<RwLock<CoordinationStatistics>>,
    event_sender: mpsc::UnboundedSender<CoordinationEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<CoordinationEvent>>>>,
}

/// Coordination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationConfig {
    pub cluster_name: String,
    pub node_role: NodeRole,
    pub communication: communication::CommunicationConfig,
    pub discovery: discovery::DiscoveryConfig,
    pub consensus: consensus::ConsensusConfig,
    pub load_balancing: load_balancer::LoadBalancerConfig,
    pub security: security::SecurityConfig,
    pub synchronization: synchronization::SynchronizationConfig,
    pub heartbeat_interval: Duration,
    pub election_timeout: Duration,
    pub max_agents: u32,
    pub task_timeout: Duration,
    pub retry_attempts: u32,
    pub enable_encryption: bool,
    pub enable_authentication: bool,
    pub enable_authorization: bool,
    pub log_level: LogLevel,
}

/// Node role in the cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
    Observer,
}

/// Log level for coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Agent registry for tracking cluster members
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    pub agents: HashMap<Uuid, AgentInfo>,
    pub leader_id: Option<Uuid>,
    pub cluster_state: ClusterState,
    pub last_updated: DateTime<Utc>,
}

/// Information about a cluster agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: Uuid,
    pub address: SocketAddr,
    pub role: NodeRole,
    pub capabilities: Vec<AgentCapability>,
    pub load_metrics: LoadMetrics,
    pub health_status: HealthStatus,
    pub version: String,
    pub last_heartbeat: DateTime<Utc>,
    pub joined_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Agent capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AgentCapability {
    SignatureDetection,
    BehavioralAnalysis,
    MachineLearning,
    HeuristicAnalysis,
    NetworkMonitoring,
    ActivePrevention,
    QuarantineManagement,
    FileSystemRollback,
    ThreatIntelligence,
    ForensicAnalysis,
    IncidentResponse,
    ThreatHunting,
}

/// Load metrics for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
    pub active_tasks: u32,
    pub queue_size: u32,
    pub response_time: Duration,
    pub throughput: f64,
    pub error_rate: f64,
}

/// Health status of an agent
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Cluster state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterState {
    Initializing,
    Stable,
    ElectionInProgress,
    Partitioned,
    Recovering,
    Shutdown,
}

/// Task queue for distributed processing
#[derive(Debug, Clone)]
pub struct TaskQueue {
    pub pending_tasks: HashMap<Uuid, CoordinationTask>,
    pub active_tasks: HashMap<Uuid, ActiveTask>,
    pub completed_tasks: HashMap<Uuid, CompletedTask>,
    pub failed_tasks: HashMap<Uuid, FailedTask>,
    pub task_assignments: HashMap<Uuid, Uuid>, // task_id -> agent_id
    pub priority_queue: Vec<Uuid>,
    pub last_updated: DateTime<Utc>,
}

/// Coordination task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationTask {
    pub id: Uuid,
    pub task_type: TaskType,
    pub priority: TaskPriority,
    pub payload: TaskPayload,
    pub requirements: TaskRequirements,
    pub constraints: TaskConstraints,
    pub created_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub retry_count: u32,
    pub metadata: HashMap<String, String>,
}

/// Task type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskType {
    ThreatDetection,
    FileAnalysis,
    NetworkAnalysis,
    BehavioralAnalysis,
    ThreatIntelligence,
    IncidentResponse,
    ForensicAnalysis,
    SystemMaintenance,
    ConfigurationUpdate,
    HealthCheck,
}

/// Task priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Background = 4,
}

/// Task payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskPayload {
    FileAnalysis {
        file_path: String,
        file_hash: String,
        analysis_type: String,
    },
    NetworkAnalysis {
        traffic_data: Vec<u8>,
        source_ip: String,
        destination_ip: String,
    },
    ThreatIntelligence {
        ioc_data: Vec<u8>,
        source: String,
        feed_type: String,
    },
    ConfigurationUpdate {
        config_data: Vec<u8>,
        config_type: String,
        target_agents: Vec<Uuid>,
    },
    Custom {
        data: Vec<u8>,
        format: String,
    },
}

/// Task requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRequirements {
    pub required_capabilities: Vec<AgentCapability>,
    pub min_cpu: Option<f64>,
    pub min_memory: Option<u64>,
    pub min_disk: Option<u64>,
    pub max_load: Option<f64>,
    pub preferred_agents: Vec<Uuid>,
    pub excluded_agents: Vec<Uuid>,
    pub geographic_constraints: Option<GeographicConstraints>,
}

/// Geographic constraints for task assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicConstraints {
    pub allowed_regions: Vec<String>,
    pub excluded_regions: Vec<String>,
    pub data_residency_requirements: Vec<String>,
}

/// Task constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskConstraints {
    pub max_execution_time: Duration,
    pub max_memory_usage: Option<u64>,
    pub max_cpu_usage: Option<f64>,
    pub isolation_level: IsolationLevel,
    pub security_clearance: SecurityClearance,
    pub compliance_requirements: Vec<String>,
}

/// Isolation level for task execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationLevel {
    None,
    Process,
    Container,
    VirtualMachine,
    Hardware,
}

/// Security clearance level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityClearance {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

/// Active task information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTask {
    pub task: CoordinationTask,
    pub assigned_agent: Uuid,
    pub started_at: DateTime<Utc>,
    pub progress: TaskProgress,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub resource_usage: ResourceUsage,
}

/// Task progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProgress {
    pub percentage: f64,
    pub current_stage: String,
    pub stages_completed: Vec<String>,
    pub stages_remaining: Vec<String>,
    pub last_update: DateTime<Utc>,
    pub status_message: Option<String>,
}

/// Resource usage for a task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub disk_usage: u64,
    pub network_usage: u64,
    pub gpu_usage: Option<f64>,
}

/// Completed task information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedTask {
    pub task: CoordinationTask,
    pub assigned_agent: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub result: TaskResult,
    pub resource_usage: ResourceUsage,
    pub performance_metrics: PerformanceMetrics,
}

/// Failed task information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedTask {
    pub task: CoordinationTask,
    pub assigned_agent: Option<Uuid>,
    pub started_at: Option<DateTime<Utc>>,
    pub failed_at: DateTime<Utc>,
    pub error: TaskError,
    pub retry_scheduled: Option<DateTime<Utc>>,
}

/// Task execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskResult {
    Success {
        data: Vec<u8>,
        metadata: HashMap<String, String>,
    },
    PartialSuccess {
        data: Vec<u8>,
        warnings: Vec<String>,
        metadata: HashMap<String, String>,
    },
    Failure {
        error: String,
        details: HashMap<String, String>,
    },
}

/// Task execution error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskError {
    pub error_type: TaskErrorType,
    pub message: String,
    pub details: HashMap<String, String>,
    pub stack_trace: Option<String>,
    pub recoverable: bool,
}

/// Task error types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskErrorType {
    InvalidInput,
    ResourceExhausted,
    TimeoutExceeded,
    AgentUnavailable,
    SecurityViolation,
    NetworkError,
    StorageError,
    ProcessingError,
    ConfigurationError,
    UnknownError,
}

/// Performance metrics for task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub execution_time: Duration,
    pub queue_time: Duration,
    pub throughput: f64,
    pub error_rate: f64,
    pub resource_efficiency: f64,
    pub quality_score: f64,
}

/// Coordination cache for performance optimization
#[derive(Debug, Clone)]
pub struct CoordinationCache {
    pub agent_capabilities: HashMap<Uuid, Vec<AgentCapability>>,
    pub load_metrics: HashMap<Uuid, LoadMetrics>,
    pub task_assignments: HashMap<TaskType, Vec<Uuid>>,
    pub performance_history: HashMap<Uuid, Vec<PerformanceMetrics>>,
    pub network_topology: HashMap<Uuid, Vec<Uuid>>,
    pub security_tokens: HashMap<Uuid, String>,
    pub last_updated: DateTime<Utc>,
}

/// Coordination statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationStatistics {
    pub total_agents: u32,
    pub active_agents: u32,
    pub total_tasks: u64,
    pub completed_tasks: u64,
    pub failed_tasks: u64,
    pub average_task_time: Duration,
    pub cluster_uptime: Duration,
    pub leader_elections: u32,
    pub network_partitions: u32,
    pub message_throughput: f64,
    pub error_rate: f64,
    pub resource_utilization: ResourceUtilization,
    pub performance_metrics: ClusterPerformanceMetrics,
}

/// Resource utilization across the cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub average_cpu: f64,
    pub average_memory: f64,
    pub average_disk: f64,
    pub average_network: f64,
    pub peak_cpu: f64,
    pub peak_memory: f64,
    pub peak_disk: f64,
    pub peak_network: f64,
}

/// Cluster performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPerformanceMetrics {
    pub average_response_time: Duration,
    pub p95_response_time: Duration,
    pub p99_response_time: Duration,
    pub throughput: f64,
    pub availability: f64,
    pub consistency_score: f64,
    pub partition_tolerance: f64,
}

/// Coordination events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinationEvent {
    AgentJoined {
        agent_id: Uuid,
        agent_info: AgentInfo,
    },
    AgentLeft {
        agent_id: Uuid,
        reason: String,
    },
    LeaderElected {
        leader_id: Uuid,
        term: u64,
    },
    TaskAssigned {
        task_id: Uuid,
        agent_id: Uuid,
    },
    TaskCompleted {
        task_id: Uuid,
        result: TaskResult,
    },
    TaskFailed {
        task_id: Uuid,
        error: TaskError,
    },
    ClusterStateChanged {
        old_state: ClusterState,
        new_state: ClusterState,
    },
    NetworkPartition {
        affected_agents: Vec<Uuid>,
    },
    SecurityAlert {
        alert_type: String,
        details: HashMap<String, String>,
    },
}

impl AgentCoordinator {
    /// Create a new agent coordinator
    pub fn new(config: CoordinationConfig) -> Result<Self, CoordinationError> {
        let agent_id = Uuid::new_v4();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Ok(Self {
            config: config.clone(),
            agent_id,
            communication_manager: Arc::new(communication::CommunicationManager::new(config.communication.clone())?),
            discovery_service: Arc::new(discovery::DiscoveryService::new(config.discovery.clone())?),
            consensus_service: Arc::new(consensus::ConsensusService::new(config.consensus.clone())?),
            load_balancer: Arc::new(load_balancer::LoadBalancer::new(config.load_balancing.clone())?),
            security_manager: Arc::new(security::SecurityManager::new(config.security.clone())?),
            sync_manager: Arc::new(synchronization::SynchronizationManager::new(config.synchronization.clone())?),
            agent_registry: Arc::new(RwLock::new(AgentRegistry::new())),
            task_queue: Arc::new(RwLock::new(TaskQueue::new())),
            coordination_cache: Arc::new(RwLock::new(CoordinationCache::new())),
            statistics: Arc::new(RwLock::new(CoordinationStatistics::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
        })
    }
    
    /// Initialize the coordination system
    pub async fn initialize(&self) -> Result<(), CoordinationError> {
        // Initialize all components
        self.communication_manager.initialize().await?;
        self.discovery_service.initialize().await?;
        self.consensus_service.initialize().await?;
        self.load_balancer.initialize().await?;
        self.security_manager.initialize().await?;
        self.sync_manager.initialize().await?;
        
        // Start discovery and join cluster
        self.discovery_service.start().await?;
        
        Ok(())
    }
    
    /// Start the coordination system
    pub async fn start(&self) -> Result<(), CoordinationError> {
        // Start all managers
        self.communication_manager.start().await?;
        self.consensus_service.start().await?;
        self.load_balancer.start().await?;
        self.sync_manager.start().await?;
        
        // Join the cluster
        self.join_cluster().await?;
        
        Ok(())
    }
    
    /// Stop the coordination system
    pub async fn stop(&self) -> Result<(), CoordinationError> {
        // Leave the cluster gracefully
        self.leave_cluster().await?;
        
        // Stop all managers
        self.sync_manager.stop().await?;
        self.load_balancer.stop().await?;
        self.consensus_service.stop().await?;
        self.communication_manager.stop().await?;
        
        Ok(())
    }
    
    /// Submit a task for distributed execution
    pub async fn submit_task(&self, task: CoordinationTask) -> Result<Uuid, CoordinationError> {
        let task_id = task.id;
        
        // Add task to queue
        {
            let mut queue = self.task_queue.write().await;
            queue.pending_tasks.insert(task_id, task.clone());
            queue.priority_queue.push(task_id);
            queue.priority_queue.sort_by_key(|id| {
                queue.pending_tasks.get(id).map(|t| t.priority).unwrap_or(TaskPriority::Background)
            });
        }
        
        // Try to assign the task
        self.assign_task(task_id).await?;
        
        Ok(task_id)
    }
    
    /// Get task status
    pub async fn get_task_status(&self, task_id: Uuid) -> Result<TaskStatus, CoordinationError> {
        let queue = self.task_queue.read().await;
        
        if queue.pending_tasks.contains_key(&task_id) {
            Ok(TaskStatus::Pending)
        } else if let Some(active_task) = queue.active_tasks.get(&task_id) {
            Ok(TaskStatus::Running {
                progress: active_task.progress.clone(),
                assigned_agent: active_task.assigned_agent,
            })
        } else if let Some(completed_task) = queue.completed_tasks.get(&task_id) {
            Ok(TaskStatus::Completed {
                result: completed_task.result.clone(),
                execution_time: completed_task.completed_at - completed_task.started_at,
            })
        } else if let Some(failed_task) = queue.failed_tasks.get(&task_id) {
            Ok(TaskStatus::Failed {
                error: failed_task.error.clone(),
                retry_scheduled: failed_task.retry_scheduled,
            })
        } else {
            Err(CoordinationError::TaskNotFound(task_id))
        }
    }
    
    /// Get cluster statistics
    pub async fn get_statistics(&self) -> CoordinationStatistics {
        self.statistics.read().await.clone()
    }
    
    /// Get agent information
    pub async fn get_agent_info(&self, agent_id: Uuid) -> Option<AgentInfo> {
        let registry = self.agent_registry.read().await;
        registry.agents.get(&agent_id).cloned()
    }
    
    /// List all agents in the cluster
    pub async fn list_agents(&self) -> Vec<AgentInfo> {
        let registry = self.agent_registry.read().await;
        registry.agents.values().cloned().collect()
    }
    
    /// Get current leader
    pub async fn get_leader(&self) -> Option<Uuid> {
        let registry = self.agent_registry.read().await;
        registry.leader_id
    }
    
    /// Check if this agent is the leader
    pub async fn is_leader(&self) -> bool {
        let registry = self.agent_registry.read().await;
        registry.leader_id == Some(self.agent_id)
    }
    
    /// Join the cluster
    async fn join_cluster(&self) -> Result<(), CoordinationError> {
        // Implementation stub
        Ok(())
    }
    
    /// Leave the cluster
    async fn leave_cluster(&self) -> Result<(), CoordinationError> {
        // Implementation stub
        Ok(())
    }
    
    /// Assign a task to an appropriate agent
    async fn assign_task(&self, task_id: Uuid) -> Result<(), CoordinationError> {
        // Implementation stub
        Ok(())
    }
}

/// Task status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Running {
        progress: TaskProgress,
        assigned_agent: Uuid,
    },
    Completed {
        result: TaskResult,
        execution_time: chrono::Duration,
    },
    Failed {
        error: TaskError,
        retry_scheduled: Option<DateTime<Utc>>,
    },
}

/// Coordination errors
#[derive(Debug, thiserror::Error)]
pub enum CoordinationError {
    #[error("Communication error: {0}")]
    Communication(#[from] communication::CommunicationError),
    #[error("Discovery error: {0}")]
    Discovery(#[from] discovery::DiscoveryError),
    #[error("Consensus error: {0}")]
    Consensus(#[from] consensus::ConsensusError),
    #[error("Load balancing error: {0}")]
    LoadBalancing(#[from] load_balancer::LoadBalancerError),
    #[error("Security error: {0}")]
    Security(#[from] security::SecurityError),
    #[error("Synchronization error: {0}")]
    Synchronization(#[from] synchronization::SynchronizationError),
    #[error("Task not found: {0}")]
    TaskNotFound(Uuid),
    #[error("Agent not found: {0}")]
    AgentNotFound(Uuid),
    #[error("Cluster not ready")]
    ClusterNotReady,
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Network partition detected")]
    NetworkPartition,
    #[error("Leadership election in progress")]
    ElectionInProgress,
    #[error("Insufficient resources")]
    InsufficientResources,
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// Default implementations
impl Default for CoordinationConfig {
    fn default() -> Self {
        Self {
            cluster_name: "erdps-cluster".to_string(),
            node_role: NodeRole::Follower,
            communication: communication::CommunicationConfig::default(),
            discovery: discovery::DiscoveryConfig::default(),
            consensus: consensus::ConsensusConfig::default(),
            load_balancing: load_balancer::LoadBalancerConfig::default(),
            security: security::SecurityConfig::default(),
            synchronization: synchronization::SynchronizationConfig::default(),
            heartbeat_interval: Duration::from_secs(30),
            election_timeout: Duration::from_secs(15),
            max_agents: 100u32,
            task_timeout: Duration::from_secs(30),
            retry_attempts: 3,
            enable_encryption: true,
            enable_authentication: true,
            enable_authorization: true,
            log_level: LogLevel::Info,
        }
    }
}

impl AgentRegistry {
    fn new() -> Self {
        Self {
            agents: HashMap::new(),
            leader_id: None,
            cluster_state: ClusterState::Initializing,
            last_updated: Utc::now(),
        }
    }
}

impl TaskQueue {
    fn new() -> Self {
        Self {
            pending_tasks: HashMap::new(),
            active_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
            failed_tasks: HashMap::new(),
            task_assignments: HashMap::new(),
            priority_queue: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

impl CoordinationCache {
    fn new() -> Self {
        Self {
            agent_capabilities: HashMap::new(),
            load_metrics: HashMap::new(),
            task_assignments: HashMap::new(),
            performance_history: HashMap::new(),
            network_topology: HashMap::new(),
            security_tokens: HashMap::new(),
            last_updated: Utc::now(),
        }
    }
}

impl CoordinationStatistics {
    fn new() -> Self {
        Self {
            total_agents: 0,
            active_agents: 0,
            total_tasks: 0,
            completed_tasks: 0,
            failed_tasks: 0,
            average_task_time: Duration::from_secs(0),
            cluster_uptime: Duration::from_secs(0),
            leader_elections: 0,
            network_partitions: 0,
            message_throughput: 0.0,
            error_rate: 0.0,
            resource_utilization: ResourceUtilization {
                average_cpu: 0.0,
                average_memory: 0.0,
                average_disk: 0.0,
                average_network: 0.0,
                peak_cpu: 0.0,
                peak_memory: 0.0,
                peak_disk: 0.0,
                peak_network: 0.0,
            },
            performance_metrics: ClusterPerformanceMetrics {
                average_response_time: Duration::from_secs(0),
                p95_response_time: Duration::from_secs(0),
                p99_response_time: Duration::from_secs(0),
                throughput: 0.0,
                availability: 0.0,
                consistency_score: 0.0,
                partition_tolerance: 0.0,
            },
        }
    }
}

impl Default for LoadMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            network_usage: 0.0,
            active_tasks: 0,
            queue_size: 0,
            response_time: Duration::from_secs(0),
            throughput: 0.0,
            error_rate: 0.0,
        }
    }
}

impl Default for TaskRequirements {
    fn default() -> Self {
        Self {
            required_capabilities: Vec::new(),
            min_cpu: None,
            min_memory: None,
            min_disk: None,
            max_load: None,
            preferred_agents: Vec::new(),
            excluded_agents: Vec::new(),
            geographic_constraints: None,
        }
    }
}

impl Default for TaskConstraints {
    fn default() -> Self {
        Self {
            max_execution_time: Duration::from_secs(30),
            max_memory_usage: None,
            max_cpu_usage: None,
            isolation_level: IsolationLevel::Process,
            security_clearance: SecurityClearance::Internal,
            compliance_requirements: Vec::new(),
        }
    }
}
