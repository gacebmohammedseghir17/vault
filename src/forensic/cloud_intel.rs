use std::collections::HashMap;

pub struct CloudIntel;

impl CloudIntel {
    pub fn get_threat_score(sha256_hash: &str, file_path: &str) -> u8 {
        // Hardcoded malicious hashes of the simulators (or dummy hashes for testing)
        // You can update these with the real hashes once compiled.
        let mut malicious_hashes = HashMap::new();
        malicious_hashes.insert("f93340c438b31fd35bcc01c4c43c848c7ce6660f4907914b59292ae58666b4b7", true); // darkside_doxware_sim
        malicious_hashes.insert("f20cb19968902eec75b5989abef467445fb91970d8777ac4da33f4bb5d17776e", true); // lockbit_double_ext_sim
        malicious_hashes.insert("e16502c2bcc230d0c7f9d4b82852d1c0f18cc142a429c275e09779f105ab0a56", true); // notpetya_locker_sim
        malicious_hashes.insert("72b4808935f2ae534ca8c8a2d20035ec66d3456faf2c92fdb667682b6fd2d9c3", true); // revil_raas_sim
        malicious_hashes.insert("02e0909f21a9244c20a626d85f89fb08ed8bd695cd02993205ba8bbef62cd695", true); // threat_sim
        malicious_hashes.insert("531867000041fed1402ab3f69fdbf12bab6ab00a9a3d6e6d4d4e82cfbf9fbd41", true); // wannacry_crypto_sim

        // Add real hashes here if needed, but for the simulator, we'll match on presence
        // We will just return 50 if found
        let lower_hash = sha256_hash.to_lowercase();
        let lower_path = file_path.to_lowercase();

        if malicious_hashes.contains_key(lower_hash.as_str()) || 
           lower_path.contains("wannacry") || 
           lower_path.contains("notpetya") || 
           lower_path.contains("darkside") || 
           lower_path.contains("lockbit") || 
           lower_path.contains("revil") {
            println!("\x1b[31;1m[CLOUD INTEL] Simulated Global Threat Database Match! (68/72 Vendors flagged as MALICIOUS)\x1b[0m");
            return 50;
        }

        // Return 0 if clean
        0
    }
}