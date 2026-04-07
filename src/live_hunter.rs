use serde::{Deserialize, Serialize};
use std::error::Error;
use reqwest::blocking::Client;

#[derive(Deserialize, Debug)]
struct Victim {
    group_name: String,
}

pub fn fetch_active_groups() -> Result<Vec<String>, Box<dyn Error>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    // Fetch from Ransomware.live API
    let resp = client.get("https://api.ransomware.live/recentvictims")
        .send()?;

    if !resp.status().is_success() {
        return Err("API Request Failed".into());
    }

    let victims: Vec<Victim> = resp.json()?;
    
    // Extract unique group names
    let mut groups: Vec<String> = victims.into_iter()
        .map(|v| v.group_name)
        .collect();
    
    groups.sort();
    groups.dedup();

    Ok(groups)
}
