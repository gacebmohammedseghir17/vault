use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Value;
use ndarray::{Array3};
use std::error::Error;
use crate::model_hashes;
use crate::supply_chain;
use std::path::Path;

pub struct BehavioralSentinel {
    session: Session,
}

impl BehavioralSentinel {
    // 1. Load the "Yellow" Brain
    pub fn new(model_path: &str) -> Result<Self, Box<dyn Error>> {
        if !supply_chain::integrity_checks_disabled() {
            let path = Path::new(model_path);
            if path.exists() {
                if !supply_chain::verify_model_integrity(path, model_hashes::BEHAVIORAL_MODEL_SHA256_ALLOWLIST)? {
                    if let Ok(actual) = supply_chain::calculate_sha256(path) {
                        println!("\x1b[33m[DEBUG] Behavioral Hash: {}\x1b[0m", actual);
                        println!("\x1b[33m[DEBUG] Allowed Hashes: {:?}\x1b[0m", model_hashes::BEHAVIORAL_MODEL_SHA256_ALLOWLIST);
                    }
                    return Err("Model hash mismatch (behavioral_model)".into());
                }
            }
        }

        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Disable)?
            .with_intra_threads(1)?
            .with_inter_threads(1)?
            .commit_from_file(model_path)?;

        println!("   |-- [INIT] Behavioral Engine: LOADED (LSTM Architecture).");
        Ok(Self { session })
    }

    // 2. The Analysis Function (Input: 20 Events x 50 Features)
    // Returns: Threat Score (0.0 to 1.0)
    pub fn analyze_sequence(&mut self, sequence_data: Vec<f32>) -> Result<f32, Box<dyn Error>> {
        // Shape: [Batch_Size=1, Sequence=20, Features=50]
        // We reshape the flat vector into a 3D tensor for the LSTM
        let input_tensor = Array3::from_shape_vec((1, 20, 50), sequence_data)?;
        
        // Convert to ORT Value
        // Note: into_raw_vec() consumes the array, which is efficient.
        // We need to pass shape as i64 usually, or allow ort to infer from the tensor if using Value::from_array
        let input_value = Value::from_array((vec![1, 20, 50], input_tensor.into_raw_vec()))?;

        // Run Inference
        let outputs = self.session.run(ort::inputs![input_value])?;
        
        // Extract the "Ransomware" probability (Index 1)
        // Output shape is [1, 2] -> [[Safe_Score, Ransom_Score]]
        let output_tuple = outputs["output"].try_extract_tensor::<f32>()?;
        let (_, data) = output_tuple;
        
        let safe_score = data[0];
        let ransom_score = data[1];

        // Debug Print only if suspicious
        if ransom_score > 0.5 {
            println!("\x1b[33m[BEHAVIOR] Suspicious Sequence Detected: {:.2}%\x1b[0m", ransom_score * 100.0);
        }

        Ok(ransom_score)
    }
}
