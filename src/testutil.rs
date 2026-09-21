//! Minimal test helpers.
//! tests included, so hex decoding lives here.

/// Decode a hex string, panicking on malformed input.
pub fn hex(s: &str) -> Vec<u8> {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit {:?}", c as char),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd length hex string");
    b.chunks(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}

/// Decode a hex string of exactly `N` bytes.
pub fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    let v = hex(s);
    assert_eq!(v.len(), N, "expected {} bytes, got {}", N, v.len());
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

/// Encode bytes as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}
