#![no_main]
use libfuzzer_sys::fuzz_target;
use policy_engine::{SignatureVerification, load_policy_from_str};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    // Feed arbitrary UTF-8 into the policy parser — it must never panic.
    let result = load_policy_from_str(input, SignatureVerification::Disabled);
    if let Ok(loaded) = result {
        // Exercise the compiled policy to catch panics in downstream logic.
        let _engine = policy_engine::PolicyEngine::with_policy(loaded.compiled);
    }
});
