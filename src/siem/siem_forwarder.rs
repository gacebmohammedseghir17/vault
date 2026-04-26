use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;
use reqwest::blocking::Client;
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SiemAlert {
    pub timestamp: String,
    pub severity: String,
    pub event_type: String,
    pub details: String,
    pub iocs: Vec<String>,
}

lazy_static! {
    static ref SIEM_QUEUE: Mutex<Option<Sender<SiemAlert>>> = Mutex::new(None);
}

/// Start the background worker thread for the SIEM forwarder
pub fn start_siem_worker(webhook_url: String) {
    let (sender, receiver): (Sender<SiemAlert>, Receiver<SiemAlert>) = mpsc::channel();
    
    if let Ok(mut queue) = SIEM_QUEUE.lock() {
        *queue = Some(sender);
    }

    thread::spawn(move || {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        loop {
            // Block until an alert is received
            if let Ok(alert) = receiver.recv() {
                match client.post(&webhook_url).json(&alert).send() {
                    Ok(res) => {
                        if !res.status().is_success() {
                            // Log HTTP errors locally without crashing
                            eprintln!("\x1b[33m[SIEM] Warning: Failed to forward alert. HTTP Status: {}\x1b[0m", res.status());
                        }
                    }
                    Err(e) => {
                        eprintln!("\x1b[33m[SIEM] Error: Connection failed while forwarding alert: {}\x1b[0m", e);
                    }
                }
            } else {
                // The sender channel has been closed, exit the thread
                break;
            }
        }
    });
}

/// Instantaneous, non-blocking operation to push an alert to the SIEM queue
pub fn push_alert(severity: &str, event_type: &str, details: &str, iocs: Vec<String>) {
    let alert = SiemAlert {
        timestamp: Utc::now().to_rfc3339(),
        severity: severity.to_string(),
        event_type: event_type.to_string(),
        details: details.to_string(),
        iocs,
    };

    if let Ok(queue_guard) = SIEM_QUEUE.lock() {
        if let Some(sender) = queue_guard.as_ref() {
            let _ = sender.send(alert);
        }
    }
}