//! Best-effort clearing of sensitive buffers (volatile writes, C `z()` parity).

use std::sync::atomic::{compiler_fence, Ordering};

/// Zero a byte slice so the compiler cannot elide the wipe (unlike a plain loop).
pub fn secret_zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid mutable reference to a byte in `buf`.
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Pin `buf` in RAM when supported (`mlock` on Unix). Best-effort; ignores errors.
#[cfg(unix)]
pub fn try_mlock(buf: &[u8]) -> bool {
    extern "C" {
        fn mlock(addr: *const libc::c_void, len: libc::size_t) -> libc::c_int;
    }
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a valid contiguous slice.
    let rc = unsafe { mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
    rc == 0
}

#[cfg(not(unix))]
pub fn try_mlock(_buf: &[u8]) -> bool {
    false
}

/// Release a prior `try_mlock` on `buf`.
#[cfg(unix)]
pub fn try_munlock(buf: &[u8]) -> bool {
    extern "C" {
        fn munlock(addr: *const libc::c_void, len: libc::size_t) -> libc::c_int;
    }
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a valid contiguous slice.
    let rc = unsafe { munlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
    rc == 0
}

#[cfg(not(unix))]
pub fn try_munlock(_buf: &[u8]) -> bool {
    false
}

/// Wipe then optionally lock (call after filling secrets).
pub fn protect_sensitive(buf: &mut [u8], lock: bool) {
    if lock {
        let _ = try_mlock(buf);
    }
}

/// Unlock then wipe (call on drop).
pub fn release_sensitive(buf: &mut [u8]) {
    let _ = try_munlock(buf);
    secret_zeroize(buf);
}

#[cfg(unix)]
mod libc {
    pub type c_void = std::ffi::c_void;
    pub type size_t = usize;
    pub type c_int = i32;
}
