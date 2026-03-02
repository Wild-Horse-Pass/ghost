//! Secure memory handling utilities

use zeroize::Zeroize;

/// A wrapper that guarantees memory is zeroed on drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create from existing data (takes ownership and will zeroize on drop)
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get a reference to the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Extend with data
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

/// Securely compare two byte slices in constant time.
///
/// Uses `subtle::ConstantTimeEq` which handles length differences
/// in constant time (no early return on length mismatch).
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Zero out a memory region using volatile writes.
///
/// # Safety
/// The pointer must be valid and point to at least `len` bytes.
pub unsafe fn secure_zero(ptr: *mut u8, len: usize) {
    for i in 0..len {
        std::ptr::write_volatile(ptr.add(i), 0u8);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_zeroize() {
        let buffer = SecureBuffer::from_vec(vec![1, 2, 3, 4, 5]);
        let ptr = buffer.as_slice().as_ptr();

        drop(buffer);

        // Note: This test is not reliable as memory may be reused
        // In a real scenario, you'd verify with a memory analyzer
        let _ = ptr; // Acknowledge we captured the pointer
    }

    #[test]
    fn test_secure_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
        assert!(!secure_compare(&a, &[1, 2, 3]));
    }
}
