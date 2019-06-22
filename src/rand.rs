//! # Utilities for random numbers

use rand::{thread_rng, Rng};

/// Fill a buffer with random data.
///
/// ```
/// use tindercrypt::rand::fill_buf;
///
/// let mut buf = [0u8; 32];
/// fill_buf(&mut buf);
/// ```
pub fn fill_buf(buf: &mut [u8]) {
    thread_rng().fill(buf);
}
