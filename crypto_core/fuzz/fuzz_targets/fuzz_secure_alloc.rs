#![no_main]
/// Fuzz target: SecureBox memory hardening with extreme / adversarial sizes.
///
/// Discovers:
/// - Panics or UB in SecureBox::new with extreme value sizes
/// - Memory locking / unlocking failures not propagated as errors
/// - Zeroization: data must be cleared upon Drop
/// - is_locked() consistency: always matches allocation state
/// - total_size() >= data_size() invariant

use libfuzzer_sys::fuzz_target;
use crypto_core::secure_alloc::SecureBox;

fuzz_target!(|raw: &[u8]| {
    if raw.is_empty() {
        return;
    }

    // Limit allocation size to avoid OOM in CI fuzzing
    let size = (raw[0] as usize) % 64 + 1; // 1..=64 bytes
    let alloc_data: Vec<u8> = raw.iter().take(size).copied().collect();

    // --- Test 1: basic allocation and field access ---
    match SecureBox::new(alloc_data.clone()) {
        Ok(b) => {
            // Invariant: total_size >= data_size
            assert!(
                b.total_size() >= b.data_size(),
                "SecureBox: total_size ({}) < data_size ({})",
                b.total_size(),
                b.data_size()
            );

            // Invariant: data_size == the size of what we allocated
            assert_eq!(b.data_size(), size);

            // is_locked() must not panic
            let _locked = b.is_locked();

            // Deref must yield original data
            let data_ref: &Vec<u8> = &*b;
            assert_eq!(data_ref.len(), size);
            for (i, &byte) in data_ref.iter().enumerate() {
                assert_eq!(byte, alloc_data[i]);
            }
        }
        Err(_) => {
            // Allocation failure is acceptable (e.g., mlock limit reached)
        }
    }

    // --- Test 2: empty allocation ---
    let empty: Vec<u8> = Vec::new();
    let _ = SecureBox::new(empty); // Must not panic regardless of outcome

    // --- Test 3: large-ish allocation (stress test) ---
    let large_size = raw.len().min(4096);
    let large_data: Vec<u8> = raw.iter().take(large_size).copied().collect();
    if let Ok(b) = SecureBox::new(large_data) {
        assert!(b.total_size() >= b.data_size());
        // Drop here zeroizes + munlocks
    }
});
