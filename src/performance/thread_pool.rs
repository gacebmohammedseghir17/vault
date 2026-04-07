//! Optimized Thread Pool Module
//!
//! This module provides an advanced thread pool implementation with
//! CPU affinity, work stealing, and dynamic scaling capabilities.

use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use dashmap::DashMap;
use crate::performance::PerformanceError;

/// Work item that can be executed by the thread pool
type WorkItem = Box<dyn FnOnce() + Send + 'static>;

/// Thread pool configuration
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Initial number of threads
    pub initial_threads: usize,
    /// Maximum number of threads
    pub max_threads: usize,
    /// Minimum number of threads
    pub min_threads: usize,
    /// Thread idle timeout before termination
    pub idle_timeout: Duration,
    /// Work queue capacity per thread
    pub queue_capacity: usize,
    /// Enable work stealing between threads
    pub enable_work_stealing: bool,
    /// CPU affinity settings
    pub cpu_affinity: Option<Vec<usize>>,
    /// Thread priority (0-99, higher is more priority)
    pub thread_priority: Option<u8>,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        let cpu_count = num_cpus::get();
        Self {
            initial_threads: cpu_count,
            max_threads: cpu_count * 2,
            min_threads: 2,
            idle_timeout: Duration::from_secs(60),
            queue_capacity: 1000,
            enable_work_stealing: true,
            cpu_affinity: None,
            thread_priority: None,
        }
    }
}

/// Thread pool statistics
#[derive(Debug, Clone, Default)]
pub struct ThreadPoolStats {
    pub active_threads: usize,
    pub idle_threads: usize,
    pub total_tasks_executed: u64,
    pub total_tasks_queued: u64,
    pub average_task_duration: Duration,
    pub queue_utilization: f64,
    pub work_stealing_events: u64,
}

/// Thread state information
#[derive(Debug, Clone)]
struct ThreadState {
    id: usize,
    is_active: bool,
    tasks_executed: u64,
    last_activity: Instant,
    cpu_affinity: Option<usize>,
}

/// Work stealing queue for efficient task distribution
struct WorkStealingQueue {
    local_queue: VecDeque<WorkItem>,
    steal_sender: Sender<WorkItem>,
    steal_receiver: Receiver<WorkItem>,
}

impl WorkStealingQueue {
    fn new() -> Self {
        let (steal_sender, steal_receiver) = unbounded();
        Self {
            local_queue: VecDeque::new(),
            steal_sender,
            steal_receiver,
        }
    }
    
    fn push_local(&mut self, item: WorkItem) {
        self.local_queue.push_back(item);
    }
    
    fn pop_local(&mut self) -> Option<WorkItem> {
        self.local_queue.pop_front()
    }
    
    fn steal(&self) -> Option<WorkItem> {
        self.steal_receiver.try_recv().ok()
    }
    
    fn offer_for_stealing(&mut self) -> bool {
        if let Some(item) = self.local_queue.pop_back() {
            self.steal_sender.send(item).is_ok()
        } else {
            false
        }
    }
}

/// Optimized thread pool with advanced features
pub struct OptimizedThreadPool {
    config: ThreadPoolConfig,
    threads: Arc<Mutex<Vec<ThreadHandle>>>,
    work_queues: Arc<DashMap<usize, Arc<Mutex<WorkStealingQueue>>>>,
    global_queue: Arc<Mutex<VecDeque<WorkItem>>>,
    stats: Arc<Mutex<ThreadPoolStats>>,
    shutdown_sender: Sender<()>,
    shutdown_receiver: Receiver<()>,
    task_sender: Sender<WorkItem>,
    task_receiver: Receiver<WorkItem>,
}

/// Thread handle with metadata
struct ThreadHandle {
    id: usize,
    handle: JoinHandle<()>,
    state: Arc<Mutex<ThreadState>>,
}

impl OptimizedThreadPool {
    /// Create a new optimized thread pool
    pub async fn new(
        thread_count: usize,
        cpu_affinity: Option<Vec<usize>>,
    ) -> Result<Self, PerformanceError> {
        let config = ThreadPoolConfig {
            initial_threads: thread_count,
            cpu_affinity,
            ..Default::default()
        };
        
        Self::with_config(config).await
    }
    
    /// Create thread pool with custom configuration
    pub async fn with_config(config: ThreadPoolConfig) -> Result<Self, PerformanceError> {
        let (shutdown_sender, shutdown_receiver) = bounded(1);
        let (task_sender, task_receiver) = unbounded();
        
        let pool = Self {
            config: config.clone(),
            threads: Arc::new(Mutex::new(Vec::new())),
            work_queues: Arc::new(DashMap::new()),
            global_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(Mutex::new(ThreadPoolStats::default())),
            shutdown_sender,
            shutdown_receiver,
            task_sender,
            task_receiver,
        };
        
        // Initialize worker threads
        pool.initialize_threads().await?;
        
        Ok(pool)
    }
    
    /// Initialize worker threads
    async fn initialize_threads(&self) -> Result<(), PerformanceError> {
        let mut threads = self.threads.lock().map_err(|_| {
            PerformanceError::ThreadPoolError("Failed to acquire threads lock".to_string())
        })?;
        
        for i in 0..self.config.initial_threads {
            let thread_handle = self.spawn_worker_thread(i).await?;
            threads.push(thread_handle);
        }
        
        Ok(())
    }
    
    /// Spawn a new worker thread
    async fn spawn_worker_thread(&self, thread_id: usize) -> Result<ThreadHandle, PerformanceError> {
        let cpu_affinity = self.config.cpu_affinity.as_ref()
            .and_then(|affinities| affinities.get(thread_id % affinities.len()))
            .copied();
        
        let state = Arc::new(Mutex::new(ThreadState {
            id: thread_id,
            is_active: false,
            tasks_executed: 0,
            last_activity: Instant::now(),
            cpu_affinity,
        }));
        
        // Create work stealing queue for this thread
        let work_queue = Arc::new(Mutex::new(WorkStealingQueue::new()));
        self.work_queues.insert(thread_id, work_queue.clone());
        
        let thread_state = state.clone();
        let thread_work_queue = work_queue.clone();
        let global_queue = self.global_queue.clone();
        let work_queues = self.work_queues.clone();
        let stats = self.stats.clone();
        let task_receiver = self.task_receiver.clone();
        let shutdown_receiver = self.shutdown_receiver.clone();
        let config = self.config.clone();
        
        let handle = thread::spawn(move || {
            Self::worker_thread_main(
                thread_id,
                thread_state,
                thread_work_queue,
                global_queue,
                work_queues,
                stats,
                task_receiver,
                shutdown_receiver,
                config,
            );
        });
        
        Ok(ThreadHandle {
            id: thread_id,
            handle,
            state,
        })
    }
    
    /// Main worker thread function
    fn worker_thread_main(
        thread_id: usize,
        state: Arc<Mutex<ThreadState>>,
        work_queue: Arc<Mutex<WorkStealingQueue>>,
        global_queue: Arc<Mutex<VecDeque<WorkItem>>>,
        work_queues: Arc<DashMap<usize, Arc<Mutex<WorkStealingQueue>>>>,
        stats: Arc<Mutex<ThreadPoolStats>>,
        task_receiver: Receiver<WorkItem>,
        shutdown_receiver: Receiver<()>,
        config: ThreadPoolConfig,
    ) {
        // Set CPU affinity if specified
        if let Some(cpu_id) = state.lock().unwrap().cpu_affinity {
            Self::set_thread_affinity(cpu_id);
        }
        
        // Set thread priority if specified
        if let Some(priority) = config.thread_priority {
            Self::set_thread_priority(priority);
        }
        
        let mut last_steal_attempt = Instant::now();
        let steal_interval = Duration::from_millis(10);
        
        loop {
            // Check for shutdown signal
            if shutdown_receiver.try_recv().is_ok() {
                break;
            }
            
            let mut work_item = None;
            
            // 1. Try to get work from local queue
            if let Ok(mut queue) = work_queue.lock() {
                work_item = queue.pop_local();
            }
            
            // 2. Try to get work from global queue
            if work_item.is_none() {
                if let Ok(mut global) = global_queue.lock() {
                    work_item = global.pop_front();
                }
            }
            
            // 3. Try to receive work from task channel
            if work_item.is_none() {
                work_item = task_receiver.try_recv().ok();
            }
            
            // 4. Try work stealing from other threads
            if work_item.is_none() && 
               config.enable_work_stealing && 
               last_steal_attempt.elapsed() > steal_interval {
                work_item = Self::attempt_work_stealing(&work_queues, thread_id);
                last_steal_attempt = Instant::now();
                
                if work_item.is_some() {
                    if let Ok(mut stats) = stats.lock() {
                        stats.work_stealing_events += 1;
                    }
                }
            }
            
            if let Some(task) = work_item {
                // Execute the task
                let start_time = Instant::now();
                
                // Update state to active
                if let Ok(mut state) = state.lock() {
                    state.is_active = true;
                    state.last_activity = Instant::now();
                }
                
                // Execute the task
                task();
                
                let execution_time = start_time.elapsed();
                
                // Update statistics
                if let Ok(mut stats) = stats.lock() {
                    stats.total_tasks_executed += 1;
                    stats.average_task_duration = 
                        (stats.average_task_duration + execution_time) / 2;
                }
                
                // Update state to idle
                if let Ok(mut state) = state.lock() {
                    state.is_active = false;
                    state.tasks_executed += 1;
                    state.last_activity = Instant::now();
                }
            } else {
                // No work available, sleep briefly
                thread::sleep(Duration::from_millis(1));
                
                // Check if thread should be terminated due to inactivity
                if let Ok(state) = state.lock() {
                    if state.last_activity.elapsed() > config.idle_timeout {
                        // Thread termination logic - graceful shutdown with timeout
        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                warn!("Thread failed to join cleanly: {:?}", e);
            }
        }
                        break;
                    }
                }
            }
        }
    }
    
    /// Attempt to steal work from other threads
    fn attempt_work_stealing(
        work_queues: &DashMap<usize, Arc<Mutex<WorkStealingQueue>>>,
        current_thread_id: usize,
    ) -> Option<WorkItem> {
        for entry in work_queues.iter() {
            let thread_id = *entry.key();
            if thread_id != current_thread_id {
                if let Ok(queue) = entry.value().lock() {
                    if let Some(work_item) = queue.steal() {
                        return Some(work_item);
                    }
                }
            }
        }
        None
    }
    
    /// Set CPU affinity for current thread (Windows-specific)
    #[cfg(windows)]
    fn set_thread_affinity(cpu_id: usize) {
        use winapi::um::processthreadsapi::GetCurrentThread;
        use winapi::um::winbase::SetThreadAffinityMask;
        
        unsafe {
            let thread_handle = GetCurrentThread();
            let affinity_mask = 1usize << cpu_id;
            SetThreadAffinityMask(thread_handle, affinity_mask);
        }
    }
    
    /// Set CPU affinity for current thread (Unix-specific)
    #[cfg(unix)]
    fn set_thread_affinity(cpu_id: usize) {
        // Unix implementation would go here
        // This is a placeholder for cross-platform compatibility
        let _ = cpu_id;
    }
    
    /// Set thread priority (Windows-specific)
    #[cfg(windows)]
    fn set_thread_priority(priority: u8) {
        use winapi::um::processthreadsapi::{GetCurrentThread, SetThreadPriority};
        use winapi::um::winbase::*;
        
        let win_priority = match priority {
            0..=20 => THREAD_PRIORITY_LOWEST,
            21..=40 => THREAD_PRIORITY_BELOW_NORMAL,
            41..=60 => THREAD_PRIORITY_NORMAL,
            61..=80 => THREAD_PRIORITY_ABOVE_NORMAL,
            81..=99 => THREAD_PRIORITY_HIGHEST,
            _ => THREAD_PRIORITY_NORMAL,
        };
        
        unsafe {
            let thread_handle = GetCurrentThread();
            SetThreadPriority(thread_handle, win_priority as i32);
        }
    }
    
    /// Set thread priority (Unix-specific)
    #[cfg(unix)]
    fn set_thread_priority(priority: u8) {
        // Unix implementation would go here
        let _ = priority;
    }
    
    /// Submit a task to the thread pool
    pub async fn execute<F>(&self, task: F) -> Result<(), PerformanceError>
    where
        F: FnOnce() + Send + 'static,
    {
        let work_item = Box::new(task);
        
        // Update queued tasks counter
        if let Ok(mut stats) = self.stats.lock() {
            stats.total_tasks_queued += 1;
        }
        
        // Try to send to task channel first
        if self.task_sender.send(work_item).is_err() {
            return Err(PerformanceError::ThreadPoolError(
                "Failed to submit task to thread pool".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Scale up the thread pool by adding more threads
    pub async fn scale_up(&self) -> Result<(), PerformanceError> {
        let mut threads = self.threads.lock().map_err(|_| {
            PerformanceError::ThreadPoolError("Failed to acquire threads lock".to_string())
        })?;
        
        if threads.len() < self.config.max_threads {
            let new_thread_id = threads.len();
            let thread_handle = self.spawn_worker_thread(new_thread_id).await?;
            threads.push(thread_handle);
        }
        
        Ok(())
    }
    
    /// Scale down the thread pool by removing idle threads
    pub async fn scale_down(&self) -> Result<(), PerformanceError> {
        let mut threads = self.threads.lock().map_err(|_| {
            PerformanceError::ThreadPoolError("Failed to acquire threads lock".to_string())
        })?;
        
        if threads.len() > self.config.min_threads {
            // Find an idle thread to remove
            if let Some(pos) = threads.iter().position(|t| {
                if let Ok(state) = t.state.lock() {
                    !state.is_active && state.last_activity.elapsed() > self.config.idle_timeout
                } else {
                    false
                }
            }) {
                let thread_handle = threads.remove(pos);
                self.work_queues.remove(&thread_handle.id);
                // Note: In a real implementation, we'd need to signal the thread to shutdown
            }
        }
        
        Ok(())
    }
    
    /// Get current thread pool statistics
    pub async fn get_stats(&self) -> ThreadPoolStats {
        if let Ok(stats) = self.stats.lock() {
            let mut current_stats = stats.clone();
            
            // Update active/idle thread counts
            if let Ok(threads) = self.threads.lock() {
                let mut active_count = 0;
                let mut idle_count = 0;
                
                for thread in threads.iter() {
                    if let Ok(state) = thread.state.lock() {
                        if state.is_active {
                            active_count += 1;
                        } else {
                            idle_count += 1;
                        }
                    }
                }
                
                current_stats.active_threads = active_count;
                current_stats.idle_threads = idle_count;
            }
            
            // Calculate queue utilization
            let total_capacity = self.config.queue_capacity * self.work_queues.len();
            let current_queue_size = self.work_queues.iter()
                .map(|entry| {
                    entry.value().lock().map(|q| q.local_queue.len()).unwrap_or(0)
                })
                .sum::<usize>();
            
            current_stats.queue_utilization = if total_capacity > 0 {
                current_queue_size as f64 / total_capacity as f64
            } else {
                0.0
            };
            
            current_stats
        } else {
            ThreadPoolStats::default()
        }
    }
    
    /// Shutdown the thread pool gracefully
    pub async fn shutdown(&self) -> Result<(), PerformanceError> {
        // Send shutdown signal to all threads
        for _ in 0..self.config.max_threads {
            let _ = self.shutdown_sender.send(());
        }
        
        // Wait for all threads to complete
        if let Ok(mut threads) = self.threads.lock() {
            while let Some(thread_handle) = threads.pop() {
                if let Err(_) = thread_handle.handle.join() {
                    // Log thread join error
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::test;
    
    #[test]
    async fn test_thread_pool_creation() {
        let pool = OptimizedThreadPool::new(4, None).await;
        assert!(pool.is_ok());
    }
    
    #[test]
    async fn test_task_execution() {
        let pool = OptimizedThreadPool::new(2, None).await.unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        
        // Submit multiple tasks
        for _ in 0..10 {
            let counter_clone = counter.clone();
            pool.execute(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }).await.unwrap();
        }
        
        // Wait a bit for tasks to complete
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }
    
    #[test]
    async fn test_thread_pool_stats() {
        let pool = OptimizedThreadPool::new(2, None).await.unwrap();
        
        // Submit a task
        pool.execute(|| {
            thread::sleep(Duration::from_millis(10));
        }).await.unwrap();
        
        // Wait for task completion
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        let stats = pool.get_stats().await;
        assert!(stats.total_tasks_queued > 0);
    }
    
    #[test]
    async fn test_thread_pool_scaling() {
        let mut config = ThreadPoolConfig::default();
        config.initial_threads = 2;
        config.max_threads = 4;
        
        let pool = OptimizedThreadPool::with_config(config).await.unwrap();
        
        // Scale up
        pool.scale_up().await.unwrap();
        
        let stats = pool.get_stats().await;
        assert!(stats.active_threads + stats.idle_threads >= 2);
    }
}
