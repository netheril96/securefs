use std::cell::RefCell;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

thread_local!(static RNG: RefCell<rand_chacha::ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_os_rng()));

pub fn fill_with_random(buffer: &mut [u8]) {
    RNG.with_borrow_mut(|rng| {
        rng.set_stream(
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("Time operations should not fail")
                .as_secs(),
        );
        rng.fill_bytes(buffer);
    });
}
