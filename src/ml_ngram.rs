use iced_x86::{Decoder, DecoderOptions, Instruction};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Value;
use ndarray::Array1;
use twox_hash::XxHash64;
use std::hash::Hasher;

const FEATURE_DIM: usize = 4096; // Must match dataset_gen.rs

pub struct NgramEngine {
    session: Option<Session>,
}

impl NgramEngine {
    pub fn new(model_path: &str) -> Self {
        let session = Session::builder()
            .ok()
            .and_then(|builder| {
                builder
                    .with_optimization_level(GraphOptimizationLevel::Level3)
                    .ok()
            })
            .and_then(|builder| builder.with_intra_threads(1).ok()) // Sequential execution is faster for single files
            .and_then(|builder| builder.commit_from_file(model_path).ok());

        Self { session }
    }

    pub fn extract_features(&self, bytes: &[u8]) -> Array1<f32> {
        let mut vector = Array1::<f32>::zeros(FEATURE_DIM);
        
        if bytes.len() < 64 { return vector; }

        let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut mnemonics: Vec<u16> = Vec::with_capacity(10000);
        
        let mut count = 0;
        while decoder.can_decode() && count < 10000 {
            decoder.decode_out(&mut instruction);
            mnemonics.push(instruction.mnemonic() as u16);
            count += 1;
        }

        if mnemonics.len() < 3 { return vector; }

        // EXACT REPLICA OF TRAINING LOGIC
        for window in mnemonics.windows(3) {
            let mut hasher = XxHash64::with_seed(0);
            hasher.write_u16(window[0]);
            hasher.write_u16(window[1]);
            hasher.write_u16(window[2]);
            let index = (hasher.finish() as usize) % FEATURE_DIM;
            vector[index] += 1.0;
        }

        let magnitude = vector.dot(&vector).sqrt();
        if magnitude > 0.0 {
            vector.mapv_inplace(|x| x / magnitude);
        }

        vector
    }

    pub fn predict(&mut self, features: &Array1<f32>) -> f32 {
        if let Some(session) = &mut self.session {
            let shape = vec![1, FEATURE_DIM];
            let data = features.to_vec();
            
            if let Ok(input_value) = Value::from_array((shape, data.into_boxed_slice())) {
                let inputs = ort::inputs!["float_input" => input_value]; // LightGBM expects "float_input"
                
                if let Ok(outputs) = session.run(inputs) {
                    // LightGBM ONNX outputs: [label, probabilities]
                    // We want probabilities (Index 1)
                    if let Ok((_, map)) = outputs[1].try_extract_tensor::<f32>() {
                        // Map is [Safe_Prob, Malicious_Prob]
                        if let Some(malicious_prob) = map.get(1) {
                            return *malicious_prob;
                        }
                    }
                }
            }
        }
        0.0
    }
}
