use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::panic::{catch_unwind, AssertUnwindSafe};

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;

fn optimize_one(model_stem: &str, manifest_dir: &Path, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = manifest_dir.join(format!("{model_stem}.onnx"));
    if !input_path.exists() {
        println!("cargo:warning=Model not found, skipping optimization: {}", input_path.display());
        return Ok(());
    }

    let baked_dir = manifest_dir.join("optimized_models");
    fs::create_dir_all(&baked_dir)?;
    let baked_path = baked_dir.join(format!("{model_stem}_optimized.onnx"));

    let enable_aot = env::var("ERDPS_AOT_OPT")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if enable_aot {
        let out_path = out_dir.join(format!("{model_stem}_optimized.onnx"));
        println!("cargo:warning=Attempting AOT optimization (ERDPS_AOT_OPT=1): {}", model_stem);

        let aot_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = ort::init().with_name("build_optimizer").commit();
            Session::builder()
                .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Level3))
                .and_then(|b| b.with_optimized_model_path(&out_path))
                .and_then(|b| b.commit_from_file(&input_path))
                .map(|_| ())
        }));

        match aot_result {
            Ok(Ok(())) => {
                fs::copy(&out_path, &baked_path)?;
                println!("cargo:warning=Baked optimized model: {}", baked_path.display());
            }
            _ => {
                fs::copy(&input_path, &baked_path)?;
                println!(
                    "cargo:warning=AOT optimization skipped (ORT/DLL mismatch). Copied quantized model: {}",
                    baked_path.display()
                );
            }
        }
    } else {
        fs::copy(&input_path, &baked_path)?;
        println!(
            "cargo:warning=AOT optimization disabled. Copied quantized model: {}",
            baked_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", input_path.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);

    let models = ["static_model_2024_quantized", "behavioral_model_quantized"];
    for model in models {
        optimize_one(model, &manifest_dir, &out_dir)?;
    }

    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
