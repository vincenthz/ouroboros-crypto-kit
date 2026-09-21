//! libsodium's initialization, guarded allocation, memory locking and
//! comparison helpers, and its CSPRNG.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::alloc::{Layout, alloc, dealloc};

/// Bytes reserved in front of a `sodium_malloc` allocation to record its size,
/// which `sodium_free` needs and its caller does not pass. Also the alignment of
/// the returned pointer, which is therefore good enough for anything the caller
/// may store there.
const HEADER: usize = 32;

unsafe extern "C" {
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    fn getentropy(buf: *mut u8, len: usize) -> c_int;
}

#[unsafe(no_mangle)]
pub extern "C" fn sodium_init() -> c_int {
    // There is nothing to initialize; libsodium returns 0 on the first call and
    // 1 if it had already been initialized, and callers accept either.
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sodium_version_string() -> *const c_char {
    c"ouroboros-crypto-kit".as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_malloc(size: usize) -> *mut c_void {
    unsafe {
        let Some(total) = size.checked_add(HEADER) else {
            return ptr::null_mut();
        };
        let Ok(layout) = Layout::from_size_align(total, HEADER) else {
            return ptr::null_mut();
        };
        let base = alloc(layout);
        if base.is_null() {
            return ptr::null_mut();
        }
        (base as *mut usize).write(size);
        base.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_free(p: *mut c_void) {
    unsafe {
        if p.is_null() {
            return;
        }
        let base = (p as *mut u8).sub(HEADER);
        let size = (base as *const usize).read();
        // libsodium wipes an allocation before releasing it.
        ptr::write_bytes(p as *mut u8, 0, size);
        dealloc(
            base,
            Layout::from_size_align_unchecked(size + HEADER, HEADER),
        );
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_mlock(addr: *mut c_void, len: usize) -> c_int {
    unsafe {
        if len == 0 {
            return 0;
        }
        mlock(addr, len)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_munlock(addr: *mut c_void, len: usize) -> c_int {
    unsafe {
        // libsodium zeroes the memory before unlocking it, so that the contents
        // cannot reach the swap afterwards.
        ptr::write_bytes(addr as *mut u8, 0, len);
        if len == 0 {
            return 0;
        }
        munlock(addr, len)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_memzero(p: *mut c_void, len: usize) {
    unsafe {
        if p.is_null() || len == 0 {
            return;
        }
        ptr::write_bytes(p as *mut u8, 0, len);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Compare two byte strings as little-endian numbers, without branching on
/// their contents, exactly as libsodium's own implementation does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_compare(b1: *const c_void, b2: *const c_void, len: usize) -> c_int {
    unsafe {
        let a = super::as_slice(b1 as *const u8, len);
        let b = super::as_slice(b2 as *const u8, len);
        let mut gt: u32 = 0;
        let mut eq: u32 = 1;
        for i in (0..len).rev() {
            let x = a[i] as u32;
            let y = b[i] as u32;
            gt |= (y.wrapping_sub(x) >> 8) & eq;
            eq &= (((y ^ x).wrapping_sub(1)) >> 8) & 1;
        }
        (gt + gt + eq) as c_int - 1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_memcmp(b1: *const c_void, b2: *const c_void, len: usize) -> c_int {
    unsafe {
        let a = super::as_slice(b1 as *const u8, len);
        let b = super::as_slice(b2 as *const u8, len);
        let mut d: u8 = 0;
        for i in 0..len {
            d |= a[i] ^ b[i];
        }
        if d == 0 { 0 } else { -1 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sodium_is_zero(n: *const u8, nlen: usize) -> c_int {
    unsafe {
        let mut d: u8 = 0;
        for b in super::as_slice(n, nlen) {
            d |= *b;
        }
        c_int::from(d == 0)
    }
}

/// Fill `buf` from the operating system's CSPRNG.
///
/// `getentropy` is limited to 256 bytes per call, hence the loop; a failure
/// falls back to `/dev/urandom`, and if that fails too there is nothing safe
/// left to do but abort, which is also what libsodium does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn randombytes_buf(buf: *mut c_void, size: usize) {
    unsafe {
        if size == 0 {
            return;
        }
        let out = slice_mut(buf as *mut u8, size);
        for chunk in out.chunks_mut(256) {
            if getentropy(chunk.as_mut_ptr(), chunk.len()) != 0 {
                fill_from_urandom(chunk);
            }
        }
    }
}

unsafe fn slice_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

fn fill_from_urandom(out: &mut [u8]) {
    use std::io::Read;
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(out)) {
        Ok(()) => (),
        Err(_) => std::process::abort(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malloc_free_round_trip() {
        unsafe {
            let p = sodium_malloc(64) as *mut u8;
            assert!(!p.is_null());
            assert_eq!(sodium_mlock(p as *mut c_void, 64), 0);
            ptr::write_bytes(p, 0xaa, 64);
            assert_eq!(*p.add(63), 0xaa);
            assert_eq!(sodium_munlock(p as *mut c_void, 64), 0);
            sodium_free(p as *mut c_void);
            sodium_free(ptr::null_mut());
        }
    }

    #[test]
    fn compare_orders_little_endian() {
        let a = [0u8, 0, 0, 1];
        let b = [1u8, 0, 0, 0];
        unsafe {
            // a is the larger number: its most significant byte is the last one
            assert_eq!(
                sodium_compare(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 4),
                1
            );
            assert_eq!(
                sodium_compare(b.as_ptr() as *const c_void, a.as_ptr() as *const c_void, 4),
                -1
            );
            assert_eq!(
                sodium_compare(a.as_ptr() as *const c_void, a.as_ptr() as *const c_void, 4),
                0
            );
        }
    }

    #[test]
    fn random_bytes_are_written() {
        // 600 bytes exercises the getentropy chunking loop
        let mut buf = [0u8; 600];
        unsafe { randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len()) };
        assert!(buf.iter().any(|b| *b != 0));
    }
}
